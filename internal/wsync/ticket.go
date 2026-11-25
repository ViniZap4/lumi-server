package wsync

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// WS tickets (SPEC: POST /api/vaults/:vault/notes/:id/ws-ticket).
//
// Browsers cannot set headers on a WebSocket upgrade, so the sync socket
// historically took the long-lived session token in ?token=, where it ends
// up in proxy logs and browser history. A ticket is a short-lived,
// single-use credential minted over an authenticated REST call and
// presented as ?ticket= instead:
//
//   - opaque: TicketBytes of crypto/rand, base64url without padding;
//   - single use: consumed atomically on the first upgrade that presents it,
//     whether or not the rest of the upgrade then succeeds;
//   - TicketTTL lifetime;
//   - bound to (user, session, vault, note): the binding is checked on
//     consumption and the session is re-validated, so logging out kills
//     outstanding tickets;
//   - stored in memory only, keyed by SHA-256 of the ticket (a heap dump
//     does not yield presentable tickets), bounded globally and per user,
//     swept lazily.
//
// Credentials accepted on the sync upgrade, in order: ?ticket= (preferred
// for browsers); X-Lumi-Token / Authorization: Bearer headers (native
// clients, not deprecated); ?token= (DEPRECATED, logged at debug).
//
// ?token= removal plan: (1) this release adds tickets and keeps ?token=;
// web and Apple clients switch to tickets. (2) Once the access log shows
// no ?token= upgrades for one release cycle, ?token= is refused with 4401
// and dropped from auth.isQueryTokenAllowed for the sync path. (3) The
// next protocol bump removes the code.
//
// Tickets are per process: a multi-replica deployment needs sticky routing
// between the ticket POST and the upgrade (the same holds for the hub).

const (
	// TicketTTL is how long a minted ticket stays presentable.
	TicketTTL = 30 * time.Second
	// TicketBytes is the ticket entropy (≥ 32 bytes by contract).
	TicketBytes = 32
	// DefaultMaxTickets caps outstanding tickets process-wide.
	DefaultMaxTickets = 10000
	// MaxTicketsPerUser caps one user's outstanding tickets. A client mints
	// one per (re)connect, so this is far above legitimate use.
	MaxTicketsPerUser = 64
)

var (
	// ErrTicketInvalid covers unknown, expired and already-used tickets
	// alike; callers must not distinguish them to the client.
	ErrTicketInvalid = errors.New("wsync: ticket invalid")
	// ErrTicketCapacity: the global table is full (after a sweep).
	ErrTicketCapacity = errors.New("wsync: ticket table full")
	// ErrTicketUserLimit: the user has too many outstanding tickets.
	ErrTicketUserLimit = errors.New("wsync: too many outstanding tickets")
)

// TicketBinding is what a ticket authorises.
type TicketBinding struct {
	UserID uuid.UUID
	// Session is the session token the ticket was minted under. Kept so
	// the socket can be re-validated against that session for its whole
	// life (logout / revocation closes it with 4401).
	Session string
	VaultID uuid.UUID
	NoteID  string
	// CRDTEpoch is the note's CRDT lineage when the ticket was minted
	// (empty when the handler has no epoch lookup). A redeem against a
	// note whose epoch has changed since is refused (4401 ticket_stale),
	// so a client never joins a history other than the one the ticket
	// response told it about.
	CRDTEpoch string
	// ReadOnly marks a ticket minted with mode "read": the socket needs
	// only note.read and never applies an update.
	ReadOnly bool
}

type ticketEntry struct {
	binding   TicketBinding
	expiresAt time.Time
}

// TicketStore is the in-memory ticket table. Safe for concurrent use.
type TicketStore struct {
	mu         sync.Mutex
	entries    map[[sha256.Size]byte]ticketEntry
	perUser    map[uuid.UUID]int
	ttl        time.Duration
	max        int
	maxPerUser int
	lastSweep  time.Time
	now        func() time.Time
}

// NewTicketStore returns a store with the default TTL and bounds.
func NewTicketStore() *TicketStore {
	return &TicketStore{
		entries:    make(map[[sha256.Size]byte]ticketEntry),
		perUser:    make(map[uuid.UUID]int),
		ttl:        TicketTTL,
		max:        DefaultMaxTickets,
		maxPerUser: MaxTicketsPerUser,
		now:        time.Now,
	}
}

func hashTicket(t string) [sha256.Size]byte { return sha256.Sum256([]byte(t)) }

// Issue mints a ticket for b and returns it with its expiry.
func (s *TicketStore) Issue(b TicketBinding) (string, time.Time, error) {
	buf := make([]byte, TicketBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", time.Time{}, fmt.Errorf("wsync: ticket entropy: %w", err)
	}
	ticket := base64.RawURLEncoding.EncodeToString(buf)

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	s.sweepLocked(now, false)
	if s.perUser[b.UserID] >= s.maxPerUser {
		s.sweepLocked(now, true)
		if s.perUser[b.UserID] >= s.maxPerUser {
			return "", time.Time{}, ErrTicketUserLimit
		}
	}
	if len(s.entries) >= s.max {
		s.sweepLocked(now, true)
		if len(s.entries) >= s.max {
			return "", time.Time{}, ErrTicketCapacity
		}
	}
	exp := now.Add(s.ttl)
	s.entries[hashTicket(ticket)] = ticketEntry{binding: b, expiresAt: exp}
	s.perUser[b.UserID]++
	return ticket, exp, nil
}

// Consume atomically removes the ticket and returns its binding. Unknown,
// expired and reused tickets all yield ErrTicketInvalid.
func (s *TicketStore) Consume(ticket string) (TicketBinding, error) {
	if ticket == "" || len(ticket) > 128 {
		return TicketBinding{}, ErrTicketInvalid
	}
	k := hashTicket(ticket)
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[k]
	if !ok {
		return TicketBinding{}, ErrTicketInvalid
	}
	s.removeLocked(k, e)
	if !s.now().Before(e.expiresAt) {
		return TicketBinding{}, ErrTicketInvalid
	}
	return e.binding, nil
}

// Len reports outstanding (possibly expired, not yet swept) tickets.
func (s *TicketStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

func (s *TicketStore) removeLocked(k [sha256.Size]byte, e ticketEntry) {
	delete(s.entries, k)
	if n := s.perUser[e.binding.UserID] - 1; n > 0 {
		s.perUser[e.binding.UserID] = n
	} else {
		delete(s.perUser, e.binding.UserID)
	}
}

// sweepLocked drops expired entries. Without force it runs at most once
// per TTL, keeping Issue O(1) amortised.
func (s *TicketStore) sweepLocked(now time.Time, force bool) {
	if !force && now.Sub(s.lastSweep) < s.ttl {
		return
	}
	s.lastSweep = now
	for k, e := range s.entries {
		if !now.Before(e.expiresAt) {
			s.removeLocked(k, e)
		}
	}
}
