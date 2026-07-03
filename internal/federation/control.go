// F3 control plane: home authors ONE signed control-state document per vault
// (roles + members + name, versioned by seq), pushes it to followers over
// the relay link, and followers answer authorization for federated vaults
// from the replicated document instead of local membership. Full-state
// replication is idempotent — no event ordering, no replay windows.
package federation

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/capguard"
	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/members"
)

// controlSigPrefix versions the signed control document.
const controlSigPrefix = "lumi-federation-control-v1"

// controlSigMessage binds the signature to the vault and the exact JSON
// bytes on the wire. seq is NOT duplicated here — it lives inside the
// signed JSON — so followers verify the signature BEFORE parsing anything
// from the untrusted payload.
func controlSigMessage(vaultID uuid.UUID, stateJSON []byte) []byte {
	head := controlSigPrefix + "|" + vaultID.String() + "|"
	out := make([]byte, 0, len(head)+len(stateJSON))
	out = append(out, head...)
	return append(out, stateJSON...)
}

// ---- document shape ----------------------------------------------------------------

type ControlRole struct {
	Name         string   `json:"name"`
	Capabilities []string `json:"capabilities"`
	IsSeed       bool     `json:"is_seed"`
}

type ControlMember struct {
	Key  string `json:"key"` // username@server-base-url
	Role string `json:"role"`
}

type ControlState struct {
	V       int             `json:"v"`
	VaultID uuid.UUID       `json:"vault_id"`
	Seq     int64           `json:"seq"`
	Name    string          `json:"name"`
	Roles   []ControlRole   `json:"roles"`
	Members []ControlMember `json:"members"`
}

// ---- storage + collaborator boundaries -----------------------------------------------

type ControlStateRepo interface {
	Get(ctx context.Context, vaultID uuid.UUID) (seq int64, state, sig []byte, err error)
	Upsert(ctx context.Context, vaultID uuid.UUID, seq int64, state, sig []byte) error
}

type ReplicatedControlRepo interface {
	Get(ctx context.Context, vaultID uuid.UUID) (seq int64, state []byte, err error)
	Upsert(ctx context.Context, vaultID uuid.UUID, seq int64, state []byte) error
}

// FederatedMember is the home-side cross-server grant.
type FederatedMember struct {
	MemberKey string
	RoleID    uuid.UUID
	RoleName  string
	JoinedAt  time.Time
}

type FederatedMemberRepo interface {
	Add(ctx context.Context, vaultID uuid.UUID, memberKey string, roleID uuid.UUID, addedBy uuid.UUID) error
	ChangeRole(ctx context.Context, vaultID uuid.UUID, memberKey string, roleID uuid.UUID) error
	Remove(ctx context.Context, vaultID uuid.UUID, memberKey string) error
	ListForVault(ctx context.Context, vaultID uuid.UUID) ([]FederatedMember, error)
}

// ControlMemberLister exposes home's local member list with usernames+roles.
type ControlMemberLister interface {
	List(ctx context.Context, vaultID uuid.UUID) ([]members.MemberJoined, error)
}

type RoleLister interface {
	ListForVault(ctx context.Context, vaultID uuid.UUID) ([]domain.Role, error)
	Get(ctx context.Context, vaultID, roleID uuid.UUID) (domain.Role, error)
}

type AckRecorder interface {
	UpdateLastAcked(ctx context.Context, vaultID uuid.UUID, peerURL string, seq int64) error
}

// ControlPusher fans a fresh signed state to live home-role links.
// Implemented by *Links.
type ControlPusher interface {
	PushControl(vaultID uuid.UUID, state, sig []byte)
}

// ControlPlaneDeps wires the F3 surface onto the federation Service.
type ControlPlaneDeps struct {
	States     ControlStateRepo
	Replicated ReplicatedControlRepo
	FedMembers FederatedMemberRepo
	Members    ControlMemberLister
	Roles      RoleLister
	Acks       AckRecorder
	Pusher     ControlPusher
}

// SetControlPlane enables F3. Without it, F1/F2 behavior is unchanged.
func (s *Service) SetControlPlane(d ControlPlaneDeps) {
	s.control = &d
}

// ---- home side: build / sign / push ----------------------------------------------------

// MemberKey renders a local username as a federation member key.
func (s *Service) MemberKey(username string) string {
	return username + "@" + s.baseURL
}

// hasActiveHomeFederation gates control-plane work to vaults that are
// actually federated as home.
func (s *Service) hasActiveHomeFederation(ctx context.Context, vaultID uuid.UUID) bool {
	rows, err := s.federations.ListForVault(ctx, vaultID)
	if err != nil {
		return false
	}
	for _, r := range rows {
		if r.Role == "home" && r.Status == "active" {
			return true
		}
	}
	return false
}

// RebuildControlState recomputes, signs, and persists the vault's control
// document. Returns (nil, nil, 0) when the vault has no active home-role
// federation (nothing to author).
func (s *Service) RebuildControlState(ctx context.Context, vaultID uuid.UUID) (state, sig []byte, seq int64, err error) {
	if s.control == nil {
		return nil, nil, 0, nil
	}
	if !s.hasActiveHomeFederation(ctx, vaultID) {
		return nil, nil, 0, nil
	}
	v, err := s.vaults.GetByID(ctx, vaultID)
	if err != nil {
		return nil, nil, 0, err
	}
	roles, err := s.control.Roles.ListForVault(ctx, vaultID)
	if err != nil {
		return nil, nil, 0, err
	}
	local, err := s.control.Members.List(ctx, vaultID)
	if err != nil {
		return nil, nil, 0, err
	}
	fed, err := s.control.FedMembers.ListForVault(ctx, vaultID)
	if err != nil {
		return nil, nil, 0, err
	}

	prevSeq, _, _, err := s.control.States.Get(ctx, vaultID)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return nil, nil, 0, err
	}
	doc := ControlState{V: 1, VaultID: vaultID, Seq: prevSeq + 1, Name: v.Name}
	for _, r := range roles {
		caps := make([]string, len(r.Capabilities))
		for i, c := range r.Capabilities {
			caps[i] = string(c)
		}
		doc.Roles = append(doc.Roles, ControlRole{Name: r.Name, Capabilities: caps, IsSeed: r.IsSeed})
	}
	for _, m := range local {
		doc.Members = append(doc.Members, ControlMember{Key: s.MemberKey(m.User.Username), Role: m.Role.Name})
	}
	for _, m := range fed {
		doc.Members = append(doc.Members, ControlMember{Key: m.MemberKey, Role: m.RoleName})
	}

	stateJSON, err := json.Marshal(doc)
	if err != nil {
		return nil, nil, 0, err
	}
	signature := ed25519.Sign(s.priv, controlSigMessage(vaultID, stateJSON))
	if err := s.control.States.Upsert(ctx, vaultID, doc.Seq, stateJSON, signature); err != nil {
		return nil, nil, 0, err
	}
	return stateJSON, signature, doc.Seq, nil
}

// ControlChanged is the notifier target for members/roles/vaults/users
// services: rebuild and push asynchronously so write paths never block on
// federation work.
func (s *Service) ControlChanged(vaultID uuid.UUID) {
	if s.control == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		state, sig, _, err := s.RebuildControlState(ctx, vaultID)
		if err != nil || state == nil {
			return
		}
		if s.control.Pusher != nil {
			s.control.Pusher.PushControl(vaultID, state, sig)
		}
	}()
}

// CurrentControlState returns the persisted signed document, lazily
// building it the first time a link comes up.
func (s *Service) CurrentControlState(ctx context.Context, vaultID uuid.UUID) (state, sig []byte, ok bool) {
	if s.control == nil {
		return nil, nil, false
	}
	_, st, sg, err := s.control.States.Get(ctx, vaultID)
	if err == nil {
		return st, sg, true
	}
	if !errors.Is(err, domain.ErrNotFound) {
		return nil, nil, false
	}
	st, sg, seq, err := s.RebuildControlState(ctx, vaultID)
	if err != nil || seq == 0 {
		return nil, nil, false
	}
	return st, sg, true
}

// RecordControlAck stores follower replication progress.
func (s *Service) RecordControlAck(vaultID uuid.UUID, peerURL string, seq int64) {
	if s.control == nil || s.control.Acks == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.control.Acks.UpdateLastAcked(ctx, vaultID, peerURL, seq)
}

// ---- follower side: verify / apply -------------------------------------------------------

// ApplyControlState verifies and stores a control document received from
// home. Returns the follower's current cursor (which is the incoming seq
// when the document advanced state, or the existing cursor when stale).
// Errors mean verification/parse failure — callers should treat the link
// as hostile or misconfigured.
func (s *Service) ApplyControlState(ctx context.Context, vaultID uuid.UUID, peerURL string, stateJSON, sig []byte) (int64, error) {
	if s.control == nil {
		return 0, errors.New("federation: control plane not wired")
	}
	fed, err := s.federations.GetActiveByVaultAndPeer(ctx, vaultID, peerURL)
	if err != nil || fed.Role != "follower" {
		return 0, fmt.Errorf("%w: no active follower link", domain.ErrForbidden)
	}
	// Verify BEFORE parsing: nothing from the payload is interpreted until
	// home's signature over the raw bytes checks out.
	if !ed25519.Verify(ed25519.PublicKey(fed.PeerPubKey), controlSigMessage(vaultID, stateJSON), sig) {
		return 0, fmt.Errorf("%w: control state signature invalid", domain.ErrForbidden)
	}
	var doc ControlState
	if err := json.Unmarshal(stateJSON, &doc); err != nil {
		return 0, fmt.Errorf("federation: control state parse: %w", err)
	}
	if doc.V != 1 || doc.VaultID != vaultID {
		return 0, fmt.Errorf("%w: control state vault mismatch", domain.ErrValidation)
	}

	cur, _, err := s.control.Replicated.Get(ctx, vaultID)
	if err != nil && !errors.Is(err, domain.ErrNotFound) {
		return 0, err
	}
	if doc.Seq <= cur {
		return cur, nil // stale replay — ack our real cursor
	}
	if err := s.control.Replicated.Upsert(ctx, vaultID, doc.Seq, stateJSON); err != nil {
		return 0, err
	}
	// Home authors the vault name too; keep the replica row in sync.
	if v, err := s.vaults.GetByID(ctx, vaultID); err == nil && v.Name != doc.Name && s.renamer != nil {
		_ = s.renamer.UpdateName(ctx, vaultID, doc.Name, uuid.Nil, "", "")
	}
	if s.resolverCache != nil {
		s.resolverCache.invalidate(vaultID)
	}
	return doc.Seq, nil
}

// VaultRenamer lets the follower apply home-authored renames to the local
// replica row. Implemented by *vaults.Service.
type VaultRenamer interface {
	UpdateName(ctx context.Context, vaultID uuid.UUID, newName string, actor uuid.UUID, ip, ua string) error
}

// SetVaultRenamer wires replica-rename application; nil disables.
func (s *Service) SetVaultRenamer(r VaultRenamer) { s.renamer = r }

// ---- federated members (home-side admin surface) ------------------------------------------

// ValidateMemberKey enforces "<username>@<absolute http(s) url>".
func ValidateMemberKey(key string) error {
	at := strings.Index(key, "@")
	if at <= 0 || at == len(key)-1 {
		return fmt.Errorf("%w: member_key must be username@server-url", domain.ErrValidation)
	}
	if err := validateServerURL(key[at+1:]); err != nil {
		return fmt.Errorf("%w: member_key server part must be an absolute http(s) URL", domain.ErrValidation)
	}
	return nil
}

func (s *Service) AddFederatedMember(ctx context.Context, vaultID uuid.UUID, memberKey string, roleID, actor uuid.UUID, ip, ua string) error {
	if s.control == nil {
		return errors.New("federation: control plane not wired")
	}
	memberKey = strings.TrimSpace(memberKey)
	if err := ValidateMemberKey(memberKey); err != nil {
		return err
	}
	if _, err := s.control.Roles.Get(ctx, vaultID, roleID); err != nil {
		return fmt.Errorf("%w: role does not belong to vault", domain.ErrValidation)
	}
	if err := s.control.FedMembers.Add(ctx, vaultID, memberKey, roleID, actor); err != nil {
		return err
	}
	s.recordAudit(ctx, &actor, vaultID, domain.ActionMemberAdd, ip, ua, map[string]any{
		"member_key": memberKey,
		"role_id":    roleID,
		"federated":  true,
	})
	s.ControlChanged(vaultID)
	return nil
}

func (s *Service) ChangeFederatedMemberRole(ctx context.Context, vaultID uuid.UUID, memberKey string, roleID, actor uuid.UUID, ip, ua string) error {
	if s.control == nil {
		return errors.New("federation: control plane not wired")
	}
	if _, err := s.control.Roles.Get(ctx, vaultID, roleID); err != nil {
		return fmt.Errorf("%w: role does not belong to vault", domain.ErrValidation)
	}
	if err := s.control.FedMembers.ChangeRole(ctx, vaultID, strings.TrimSpace(memberKey), roleID); err != nil {
		return err
	}
	s.recordAudit(ctx, &actor, vaultID, domain.ActionMemberRoleChange, ip, ua, map[string]any{
		"member_key": memberKey,
		"role_id":    roleID,
		"federated":  true,
	})
	s.ControlChanged(vaultID)
	return nil
}

func (s *Service) RemoveFederatedMember(ctx context.Context, vaultID uuid.UUID, memberKey string, actor uuid.UUID, ip, ua string) error {
	if s.control == nil {
		return errors.New("federation: control plane not wired")
	}
	if err := s.control.FedMembers.Remove(ctx, vaultID, strings.TrimSpace(memberKey)); err != nil {
		return err
	}
	s.recordAudit(ctx, &actor, vaultID, domain.ActionMemberRemove, ip, ua, map[string]any{
		"member_key": memberKey,
		"federated":  true,
	})
	s.ControlChanged(vaultID)
	return nil
}

func (s *Service) ListFederatedMembers(ctx context.Context, vaultID uuid.UUID) ([]FederatedMember, error) {
	if s.control == nil {
		return nil, nil
	}
	return s.control.FedMembers.ListForVault(ctx, vaultID)
}

// ---- follower-side authorization resolver ---------------------------------------------------

// UserGetter resolves the local user for member-key derivation.
type UserGetter interface {
	GetByID(ctx context.Context, id uuid.UUID) (domain.User, error)
}

// resolverCacheEntry memoizes per-vault federation status + parsed state.
type resolverCacheEntry struct {
	isFollower bool
	seq        int64
	doc        *ControlState
	expires    time.Time
}

type resolverCache struct {
	mu  sync.Mutex
	m   map[uuid.UUID]resolverCacheEntry
	ttl time.Duration
	now func() time.Time
}

func newResolverCache(ttl time.Duration) *resolverCache {
	return &resolverCache{m: map[uuid.UUID]resolverCacheEntry{}, ttl: ttl, now: time.Now}
}

func (c *resolverCache) get(vaultID uuid.UUID) (resolverCacheEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.m[vaultID]
	if !ok || e.expires.Before(c.now()) {
		return resolverCacheEntry{}, false
	}
	return e, true
}

func (c *resolverCache) put(vaultID uuid.UUID, e resolverCacheEntry) {
	e.expires = c.now().Add(c.ttl)
	c.mu.Lock()
	c.m[vaultID] = e
	c.mu.Unlock()
}

func (c *resolverCache) invalidate(vaultID uuid.UUID) {
	c.mu.Lock()
	delete(c.m, vaultID)
	c.mu.Unlock()
}

// ControlResolver wraps the normal membership resolver: for vaults this
// server FOLLOWS, authorization comes from home's replicated control state
// (member key = username@this-server). Until the first document arrives
// (bootstrap), local membership still answers so a fresh join isn't locked
// out before home has pushed state.
//
// Construction is two-phase (the resolver is needed by services the
// federation Service itself depends on): NewControlResolver first, Bind
// once the Service exists. Unbound, it transparently delegates to base.
type ControlResolver struct {
	base    capguard.Resolver
	users   UserGetter
	cache   *resolverCache
	mu      sync.RWMutex
	svc     *Service
	baseURL string
}

func NewControlResolver(base capguard.Resolver, users UserGetter) *ControlResolver {
	return &ControlResolver{
		base:  base,
		users: users,
		cache: newResolverCache(30 * time.Second),
	}
}

// Bind attaches the federation service and registers the cache so
// ApplyControlState invalidates on fresh documents.
func (r *ControlResolver) Bind(svc *Service) {
	r.mu.Lock()
	r.svc = svc
	r.baseURL = svc.baseURL
	r.mu.Unlock()
	svc.resolverCache = r.cache
}

func (r *ControlResolver) service() (*Service, string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.svc, r.baseURL
}

func (r *ControlResolver) RoleForUser(ctx context.Context, vaultID, userID uuid.UUID) (domain.Role, error) {
	svc, baseURL := r.service()
	if svc == nil {
		return r.base.RoleForUser(ctx, vaultID, userID)
	}
	entry, ok := r.cache.get(vaultID)
	if !ok {
		entry = r.load(ctx, svc, vaultID)
		r.cache.put(vaultID, entry)
	}
	if !entry.isFollower || entry.doc == nil {
		// Not federated, or bootstrap window: local membership rules.
		return r.base.RoleForUser(ctx, vaultID, userID)
	}

	u, err := r.users.GetByID(ctx, userID)
	if err != nil {
		return domain.Role{}, err
	}
	key := u.Username + "@" + baseURL
	for _, m := range entry.doc.Members {
		if m.Key != key {
			continue
		}
		for _, role := range entry.doc.Roles {
			if role.Name != m.Role {
				continue
			}
			caps := make(domain.CapabilitySet, len(role.Capabilities))
			for i, c := range role.Capabilities {
				caps[i] = domain.Capability(c)
			}
			return domain.Role{VaultID: vaultID, Name: role.Name, Capabilities: caps, IsSeed: role.IsSeed}, nil
		}
		return domain.Role{}, fmt.Errorf("federation: member role %q missing from control state: %w", m.Role, domain.ErrNotFound)
	}
	return domain.Role{}, domain.ErrNotFound
}

func (r *ControlResolver) load(ctx context.Context, svc *Service, vaultID uuid.UUID) resolverCacheEntry {
	entry := resolverCacheEntry{}
	rows, err := svc.federations.ListForVault(ctx, vaultID)
	if err != nil {
		return entry
	}
	for _, row := range rows {
		if row.Role == "follower" && row.Status == "active" {
			entry.isFollower = true
			break
		}
	}
	if !entry.isFollower || svc.control == nil {
		return entry
	}
	seq, stateJSON, err := svc.control.Replicated.Get(ctx, vaultID)
	if err != nil {
		return entry // bootstrap: no state yet
	}
	var doc ControlState
	if json.Unmarshal(stateJSON, &doc) == nil {
		entry.seq = seq
		entry.doc = &doc
	}
	return entry
}
