// Package feed implements the per-account event stream (SPEC-LIVROS §3):
// GET /api/events as Server-Sent Events, carrying only ids, seqs and
// roles. The in-process Broker receives publications from the services
// that change vaults, notes, memberships and sessions, and fans them out
// to each user's streams, filtered by capability: an event about a vault
// only reaches a stream whose user can read that vault (note.read).
//
// Single-instance by design: the broker is in memory. Multi-instance
// fan-out would ride on LISTEN/NOTIFY (spec §3.6) and is not implemented.
package feed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
)

// Wire event names (SPEC-LIVROS §3.3).
const (
	EventHello        = "hello"
	EventVaultHead    = "vault.head"
	EventVaultAccess  = "vault.access"
	EventVaultUpdated = "vault.updated"
	EventVaultRevoked = "vault.revoked"
	EventSessionEnded = "session.ended"
	EventReconnect    = "reconnect"
)

// Protocol is the feed protocol version announced in hello.
const Protocol = 1

// vault.revoked reasons.
const (
	ReasonRemoved           = "removed"
	ReasonDeleted           = "deleted"
	ReasonSeveredUnreadable = "severed_unreadable"
)

// session.ended reasons.
const (
	SessionRevoked = "revoked"
	SessionExpired = "expired"
	SessionDeleted = "deleted"
)

// VaultAccess is one readable vault as the feed reports it.
type VaultAccess struct {
	VaultID uuid.UUID
	Seq     int64
	Role    string
	CanEdit bool
}

// Directory answers what a user may read. Implementations must apply the
// same capability rule as the REST layer (note.read via the
// federation-aware resolver).
type Directory interface {
	// Readable lists every vault the user can read, with head seq, role
	// and can_edit.
	Readable(ctx context.Context, userID uuid.UUID) ([]VaultAccess, error)
	// Access resolves one vault. ok=false when the user cannot read it
	// (not a member, no note.read, vault gone).
	Access(ctx context.Context, userID, vaultID uuid.UUID) (acc VaultAccess, ok bool, err error)
}

// SessionChecker re-validates a session token WITHOUT sliding its TTL.
// reason is "" while valid, else a session.ended reason; err reports a
// transient failure (the stream is kept).
type SessionChecker func(ctx context.Context, token string) (reason string, err error)

// Config holds the feed limits (SPEC-LIVROS §3.6).
type Config struct {
	MaxStreamsPerUser int           // concurrent streams per user (16)
	OpensPerMinute    int           // stream-open bucket per user (20/min)
	Buffer            int           // queued events per stream (128)
	HeadInterval      time.Duration // vault.head coalescing window (250 ms)
	Ping              time.Duration // ": ping" interval (25 s)
	Recheck           time.Duration // session + access re-check (60 s)
	MaxLifetime       time.Duration // stream lifetime before reconnect (30 min)
	WriteGrace        time.Duration // sliding write deadline (60 s)
	ResolveTimeout    time.Duration // one Directory / checker call (5 s)
}

// DefaultConfig returns the spec limits.
func DefaultConfig() Config {
	return Config{
		MaxStreamsPerUser: 16,
		OpensPerMinute:    20,
		Buffer:            128,
		HeadInterval:      250 * time.Millisecond,
		Ping:              25 * time.Second,
		Recheck:           60 * time.Second,
		MaxLifetime:       30 * time.Minute,
		WriteGrace:        60 * time.Second,
		ResolveTimeout:    5 * time.Second,
	}
}

// Errors returned by Open.
var (
	ErrTooManyStreams = errors.New("feed: too many streams")
	ErrClosed         = errors.New("feed: broker closed")
)

// RateLimitError is returned by Open when the user's open bucket is empty.
type RateLimitError struct{ RetryAfter time.Duration }

func (e *RateLimitError) Error() string { return "feed: stream opens rate limited" }

// SessionKey is the in-memory identity of a session: SHA-256 of the raw
// token, so the broker never indexes by the credential itself.
func SessionKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// jobQueue bounds pending access re-resolutions. A dropped job heals at
// the next periodic re-check.
const jobQueue = 1024

// Broker owns every open stream.
type Broker struct {
	cfg   Config
	dir   Directory
	check SessionChecker
	log   zerolog.Logger
	now   func() time.Time

	ctx    context.Context
	cancel context.CancelFunc
	jobs   chan func(context.Context)
	wg     sync.WaitGroup

	mu     sync.Mutex
	users  map[uuid.UUID]map[*Subscriber]struct{}
	opens  map[uuid.UUID]*bucket
	closed bool
}

// NewBroker starts the broker's resolver worker. check may be nil
// (sessions are then only ended by publications).
func NewBroker(cfg Config, dir Directory, check SessionChecker, log zerolog.Logger) *Broker {
	if dir == nil {
		panic("feed.NewBroker: directory is required")
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &Broker{
		cfg:    cfg,
		dir:    dir,
		check:  check,
		log:    log.With().Str("component", "feed").Logger(),
		now:    time.Now,
		ctx:    ctx,
		cancel: cancel,
		jobs:   make(chan func(context.Context), jobQueue),
		users:  map[uuid.UUID]map[*Subscriber]struct{}{},
		opens:  map[uuid.UUID]*bucket{},
	}
	b.wg.Add(1)
	go b.worker()
	return b
}

// Close tells every stream to reconnect and stops the worker. Call it
// before shutting the HTTP server down: open streams would otherwise hold
// graceful shutdown for its whole timeout.
func (b *Broker) Close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	var subs []*Subscriber
	for _, set := range b.users {
		for s := range set {
			subs = append(subs, s)
		}
	}
	b.mu.Unlock()
	for _, s := range subs {
		s.end(frame{EventReconnect, mustJSON(reconnectPayload{AfterMS: 0})}, true)
	}
	b.cancel()
	b.wg.Wait()
}

func (b *Broker) worker() {
	defer b.wg.Done()
	for {
		select {
		case <-b.ctx.Done():
			return
		case job := <-b.jobs:
			job(b.ctx)
		}
	}
}

func (b *Broker) submit(job func(context.Context)) {
	select {
	case b.jobs <- job:
	default:
		b.log.Warn().Msg("feed: resolver queue full; access change deferred to periodic re-check")
	}
}

// ---- open / close streams ------------------------------------------------------

// Open registers a new stream for userID. The caller must then run Serve
// (which unregisters on exit).
func (b *Broker) Open(userID uuid.UUID, token string) (*Subscriber, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, ErrClosed
	}
	if limit := b.cfg.MaxStreamsPerUser; limit > 0 && len(b.users[userID]) >= limit {
		return nil, ErrTooManyStreams
	}
	if b.cfg.OpensPerMinute > 0 {
		bk := b.opens[userID]
		if bk == nil {
			bk = &bucket{tokens: float64(b.cfg.OpensPerMinute), at: b.now()}
			b.opens[userID] = bk
		}
		if wait := bk.take(b.now(), float64(b.cfg.OpensPerMinute)); wait > 0 {
			return nil, &RateLimitError{RetryAfter: wait}
		}
	}
	s := newSubscriber(userID, token, b.cfg.Buffer)
	set := b.users[userID]
	if set == nil {
		set = map[*Subscriber]struct{}{}
		b.users[userID] = set
	}
	set[s] = struct{}{}
	b.sweepBucketsLocked()
	return s, nil
}

func (b *Broker) unregister(s *Subscriber) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if set := b.users[s.userID]; set != nil {
		delete(set, s)
		if len(set) == 0 {
			delete(b.users, s.userID)
		}
	}
}

// Streams returns the number of open streams for userID (tests/metrics).
func (b *Broker) Streams(userID uuid.UUID) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.users[userID])
}

// TotalStreams returns the number of open streams across all users
// (admin status).
func (b *Broker) TotalStreams() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, set := range b.users {
		n += len(set)
	}
	return n
}

// subsOf snapshots a user's streams.
func (b *Broker) subsOf(userID uuid.UUID) []*Subscriber {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]*Subscriber, 0, len(b.users[userID]))
	for s := range b.users[userID] {
		out = append(out, s)
	}
	return out
}

// allSubs snapshots every stream, grouped by user.
func (b *Broker) allSubs() map[uuid.UUID][]*Subscriber {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[uuid.UUID][]*Subscriber, len(b.users))
	for u, set := range b.users {
		for s := range set {
			out[u] = append(out[u], s)
		}
	}
	return out
}

// ---- publications (all non-blocking) -------------------------------------------

// VaultHead announces a new seq for the vault (notes.HeadPublisher).
func (b *Broker) VaultHead(vaultID uuid.UUID, seq int64) {
	for _, subs := range b.allSubs() {
		for _, s := range subs {
			s.offerHead(vaultID, seq)
		}
	}
}

// VaultUpdated announces name/owner/federation changes.
func (b *Broker) VaultUpdated(vaultID uuid.UUID, fields ...string) {
	if fields == nil {
		fields = []string{}
	}
	data := mustJSON(updatedPayload{VaultID: vaultID, Fields: fields})
	for _, subs := range b.allSubs() {
		for _, s := range subs {
			s.sendIfReadable(vaultID, frame{EventVaultUpdated, data})
		}
	}
}

// VaultDeleted revokes the vault on every stream that could read it.
func (b *Broker) VaultDeleted(vaultID uuid.UUID) {
	for _, subs := range b.allSubs() {
		for _, s := range subs {
			s.apply(vaultID, VaultAccess{}, false, ReasonDeleted)
		}
	}
}

// AccessChanged re-resolves vault access for the given users (member
// added/removed/re-roled, invite accepted, ownership transferred, vault
// created or copied for them) and emits vault.access / vault.revoked.
func (b *Broker) AccessChanged(vaultID uuid.UUID, userIDs ...uuid.UUID) {
	users := append([]uuid.UUID(nil), userIDs...)
	b.submit(func(ctx context.Context) {
		for _, u := range users {
			b.resolveFor(ctx, u, vaultID, b.subsOf(u))
		}
	})
}

// VaultAccessChanged re-resolves vault access for every connected user
// (role capabilities edited, federation control state applied).
func (b *Broker) VaultAccessChanged(vaultID uuid.UUID) {
	b.submit(func(ctx context.Context) {
		for u, subs := range b.allSubs() {
			b.resolveFor(ctx, u, vaultID, subs)
		}
	})
}

// SessionEnded ends every stream opened with token (logout).
func (b *Broker) SessionEnded(token, reason string) {
	b.SessionKeyEnded(SessionKey(token), reason)
}

// SessionKeyEnded is SessionEnded by the session's stored hash (the
// sessions.token_hash column, equal to SessionKey of the raw token): the
// operator revokes a session without ever holding its token.
func (b *Broker) SessionKeyEnded(key, reason string) {
	for _, subs := range b.allSubs() {
		for _, s := range subs {
			if s.sessionKey == key {
				s.end(sessionEndedFrame(reason), false)
			}
		}
	}
}

// UserSessionsEnded ends every stream of the user (password change,
// erasure).
func (b *Broker) UserSessionsEnded(userID uuid.UUID, reason string) {
	for _, s := range b.subsOf(userID) {
		s.end(sessionEndedFrame(reason), false)
	}
}

func (b *Broker) resolveFor(ctx context.Context, userID, vaultID uuid.UUID, subs []*Subscriber) {
	if len(subs) == 0 {
		return
	}
	rctx, cancel := context.WithTimeout(ctx, b.cfg.ResolveTimeout)
	acc, ok, err := b.dir.Access(rctx, userID, vaultID)
	cancel()
	if err != nil {
		b.log.Warn().Err(err).Msg("feed: access resolve failed; periodic re-check will retry")
		return
	}
	for _, s := range subs {
		s.apply(vaultID, acc, ok, ReasonRemoved)
	}
}

// ---- rate limiting ----------------------------------------------------------------

type bucket struct {
	tokens float64
	at     time.Time
}

// take refills at capacity per minute and consumes one token; returns 0
// on success, else how long until a token is available.
func (bk *bucket) take(now time.Time, capacity float64) time.Duration {
	rate := capacity / 60 // tokens per second
	bk.tokens = math.Min(capacity, bk.tokens+now.Sub(bk.at).Seconds()*rate)
	bk.at = now
	if bk.tokens >= 1 {
		bk.tokens--
		return 0
	}
	return time.Duration((1 - bk.tokens) / rate * float64(time.Second))
}

// sweepBucketsLocked forgets buckets that have refilled completely and
// whose user has no stream: they carry no state worth keeping.
func (b *Broker) sweepBucketsLocked() {
	if len(b.opens) < 1024 {
		return
	}
	full := time.Minute
	for u, bk := range b.opens {
		if len(b.users[u]) == 0 && b.now().Sub(bk.at) >= full {
			delete(b.opens, u)
		}
	}
}

// ---- payloads ------------------------------------------------------------------------

type helloVault struct {
	VaultID uuid.UUID `json:"vault_id"`
	Seq     int64     `json:"seq"`
	Role    string    `json:"role"`
	CanEdit bool      `json:"can_edit"`
}

type helloPayload struct {
	Protocol   int          `json:"protocol"`
	ServerTime string       `json:"server_time"`
	UserID     uuid.UUID    `json:"user_id"`
	Vaults     []helloVault `json:"vaults"`
}

type headPayload struct {
	VaultID uuid.UUID `json:"vault_id"`
	Seq     int64     `json:"seq"`
}

type accessPayload struct {
	VaultID uuid.UUID `json:"vault_id"`
	Role    string    `json:"role"`
	CanEdit bool      `json:"can_edit"`
}

type updatedPayload struct {
	VaultID uuid.UUID `json:"vault_id"`
	Fields  []string  `json:"fields"`
}

type revokedPayload struct {
	VaultID uuid.UUID `json:"vault_id"`
	Reason  string    `json:"reason"`
}

type sessionPayload struct {
	Reason string `json:"reason"`
}

type reconnectPayload struct {
	AfterMS int64 `json:"after_ms"`
}

func helloFrame(userID uuid.UUID, now time.Time, accs []VaultAccess) frame {
	vs := make([]helloVault, 0, len(accs))
	for _, a := range accs {
		vs = append(vs, helloVault{VaultID: a.VaultID, Seq: a.Seq, Role: a.Role, CanEdit: a.CanEdit})
	}
	sort.Slice(vs, func(i, j int) bool { return vs[i].VaultID.String() < vs[j].VaultID.String() })
	return frame{EventHello, mustJSON(helloPayload{
		Protocol:   Protocol,
		ServerTime: now.UTC().Format(time.RFC3339),
		UserID:     userID,
		Vaults:     vs,
	})}
}

func sessionEndedFrame(reason string) frame {
	return frame{EventSessionEnded, mustJSON(sessionPayload{Reason: reason})}
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic("feed: marshal: " + err.Error())
	}
	return b
}
