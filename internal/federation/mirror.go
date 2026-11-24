// One-way mirrors (docs/SPEC-ESPELHO-SELADO.md part A, phase M1): a mirror
// is a federation link with mode "mirror". Home only sends on it; the
// mirror server holds a read-only copy, clamped at the capability resolver.
package federation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// Sever policies: what a mirror does with its copy when home revokes it.
const (
	SeverKeep  = "keep"
	SeverPurge = "purge"
)

// Mirror violation policy (§A11): after this many content frames from a
// mirror within the window, home revokes the link.
const (
	mirrorViolationLimit  = 3
	mirrorViolationWindow = time.Hour
)

// MirrorStore is the storage surface of mirror links (pg.FederationStore).
type MirrorStore interface {
	RecordMirrorAck(ctx context.Context, vaultID uuid.UUID, peerURL string, seq int64) error
	RecordHomeSeq(ctx context.Context, vaultID uuid.UUID, peerURL string, seq int64) error
	TouchContact(ctx context.Context, vaultID uuid.UUID, peerURL string) error
	PendingDeletes(ctx context.Context, vaultID uuid.UUID, afterSeq int64) (int64, *time.Time, error)
	VaultHead(ctx context.Context, vaultID uuid.UUID) (int64, error)
	SetPaused(ctx context.Context, id uuid.UUID, paused bool) error
	RequestResync(ctx context.Context, id uuid.UUID) error
}

// VaultDeleter drops a local vault (purge on revoke). *vaults.Service.
type VaultDeleter interface {
	Delete(ctx context.Context, vaultID, actor uuid.UUID, ip, ua string) error
}

// SetMirrorStore wires mirror bookkeeping; nil disables acks/lag.
func (s *Service) SetMirrorStore(m MirrorStore) { s.mirrors = m }

// SetVaultDeleter wires the purge sever policy; nil keeps every copy.
func (s *Service) SetVaultDeleter(d VaultDeleter) { s.deleter = d }

// ---- is this vault a mirror here? ------------------------------------------------

// mirrorCache memoizes IsMirrorVault. Invalidated by this process on join,
// revoke and promote; the TTL covers changes made by another process (the
// CLI's promote).
type mirrorCache struct {
	mu  sync.Mutex
	m   map[uuid.UUID]mirrorCacheEntry
	ttl time.Duration
}

type mirrorCacheEntry struct {
	mirror  bool
	expires time.Time
}

func newMirrorCache() *mirrorCache {
	return &mirrorCache{m: map[uuid.UUID]mirrorCacheEntry{}, ttl: 15 * time.Second}
}

func (c *mirrorCache) invalidate(vaultID uuid.UUID) {
	c.mu.Lock()
	delete(c.m, vaultID)
	c.mu.Unlock()
}

// IsMirrorVault reports whether this server holds the vault as a mirror:
// a follower-side mirror link that was not promoted, whatever its status
// (a revoked mirror keeps a frozen read-only copy). Errors answer true
// for vaults with a cached mirror entry and false otherwise.
func (s *Service) IsMirrorVault(ctx context.Context, vaultID uuid.UUID) bool {
	now := s.now()
	s.mirrorCache.mu.Lock()
	e, ok := s.mirrorCache.m[vaultID]
	s.mirrorCache.mu.Unlock()
	if ok && now.Before(e.expires) {
		return e.mirror
	}
	rows, err := s.federations.ListForVault(ctx, vaultID)
	if err != nil {
		return ok && e.mirror
	}
	mirror := false
	for _, r := range rows {
		if r.IsMirrorFollower() {
			mirror = true
			break
		}
	}
	s.mirrorCache.mu.Lock()
	s.mirrorCache.m[vaultID] = mirrorCacheEntry{mirror: mirror, expires: now.Add(s.mirrorCache.ttl)}
	s.mirrorCache.mu.Unlock()
	return mirror
}

func (s *Service) invalidateVault(vaultID uuid.UUID) {
	s.mirrorCache.invalidate(vaultID)
	if s.resolverCache != nil {
		s.resolverCache.invalidate(vaultID)
	}
}

// ---- relay callbacks -------------------------------------------------------------

// MirrorViolation (home side) records a content frame a mirror sent: the
// relay already closed the link. Three violations within an hour revoke
// the link.
func (s *Service) MirrorViolation(ctx context.Context, vaultID uuid.UUID, peerURL, frame, noteID string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	s.recordAudit(ctx, nil, vaultID, domain.ActionFederationMirrorViolation, "", "", map[string]any{
		"peer_url": peerURL,
		"frame":    frame,
		"note_id":  noteID,
	})
	key := vaultID.String() + "|" + peerURL
	now := s.now()
	s.violationsMu.Lock()
	var recent []time.Time
	for _, at := range s.violations[key] {
		if now.Sub(at) < mirrorViolationWindow {
			recent = append(recent, at)
		}
	}
	recent = append(recent, now)
	s.violations[key] = recent
	revoke := len(recent) >= mirrorViolationLimit
	if revoke {
		delete(s.violations, key)
	}
	s.violationsMu.Unlock()
	if !revoke {
		return
	}
	fed, err := s.federations.GetActiveByVaultAndPeer(ctx, vaultID, peerURL)
	if err != nil || fed.Role != "home" {
		return
	}
	if err := s.RevokeFederation(ctx, vaultID, fed.ID, uuid.Nil, "", ""); err != nil {
		return
	}
	s.recordAudit(ctx, nil, vaultID, domain.ActionFederationRevoke, "", "", map[string]any{
		"kind":     "mirror_violations",
		"peer_url": peerURL,
		"count":    len(recent),
	})
}

// RecordMirrorAck (home side) stores a mirror's acknowledged seq.
func (s *Service) RecordMirrorAck(vaultID uuid.UUID, peerURL string, seq int64) {
	if s.mirrors == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.mirrors.RecordMirrorAck(ctx, vaultID, peerURL, seq)
}

// RecordHomeSeq (mirror side) stores how far the copy is applied.
func (s *Service) RecordHomeSeq(vaultID uuid.UUID, peerURL string, seq int64) {
	if s.mirrors == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.mirrors.RecordHomeSeq(ctx, vaultID, peerURL, seq)
}

// VaultHead returns this server's seq for the vault (relay ChangesEnd).
func (s *Service) VaultHead(ctx context.Context, vaultID uuid.UUID) (int64, error) {
	if s.mirrors == nil {
		return 0, errors.New("federation: mirror store not wired")
	}
	return s.mirrors.VaultHead(ctx, vaultID)
}

// ---- link stats (home side) ------------------------------------------------------

// LinkStats is the replication state of one home-side mirror link.
type LinkStats struct {
	HeadSeq               int64
	LagSeq                int64
	PendingDeletes        int64
	OldestPendingDeleteAt *time.Time
}

// MirrorLinkStats computes lag and pending deletes of a home-side mirror
// link (zero value for other links or without a mirror store).
func (s *Service) MirrorLinkStats(ctx context.Context, f domain.Federation) LinkStats {
	if s.mirrors == nil || f.Role != "home" || f.Mode != ModeMirror {
		return LinkStats{}
	}
	var st LinkStats
	if head, err := s.mirrors.VaultHead(ctx, f.VaultID); err == nil {
		st.HeadSeq = head
		if head > f.MirrorAckedSeq {
			st.LagSeq = head - f.MirrorAckedSeq
		}
	}
	if n, oldest, err := s.mirrors.PendingDeletes(ctx, f.VaultID, f.MirrorAckedSeq); err == nil {
		st.PendingDeletes, st.OldestPendingDeleteAt = n, oldest
	}
	return st
}

// ---- operator controls -----------------------------------------------------------

// PauseLink stops a link without revoking it: a follower stops dialling,
// home refuses the challenge and drops the live session.
func (s *Service) PauseLink(ctx context.Context, id uuid.UUID) (domain.Federation, error) {
	if s.mirrors == nil {
		return domain.Federation{}, errors.New("federation: mirror store not wired")
	}
	f, err := s.federations.Get(ctx, id)
	if err != nil {
		return domain.Federation{}, err
	}
	if err := s.mirrors.SetPaused(ctx, id, true); err != nil {
		return domain.Federation{}, err
	}
	if s.relay != nil {
		s.relay.StopLink(f.VaultID, f.PeerURL)
	}
	return f, nil
}

// ResumeLink undoes PauseLink.
func (s *Service) ResumeLink(ctx context.Context, id uuid.UUID) (domain.Federation, error) {
	if s.mirrors == nil {
		return domain.Federation{}, errors.New("federation: mirror store not wired")
	}
	f, err := s.federations.Get(ctx, id)
	if err != nil {
		return domain.Federation{}, err
	}
	if err := s.mirrors.SetPaused(ctx, id, false); err != nil {
		return domain.Federation{}, err
	}
	if s.relay != nil && f.Role == "follower" && f.Status == "active" {
		s.relay.StartLink(context.WithoutCancel(ctx), f.VaultID, f.PeerURL)
	}
	return f, nil
}

// ResyncLink (mirror side) forgets the copy's progress and bounces the
// link: the next session runs a full manifest pass with a Step1 per note.
func (s *Service) ResyncLink(ctx context.Context, id uuid.UUID) (domain.Federation, error) {
	if s.mirrors == nil {
		return domain.Federation{}, errors.New("federation: mirror store not wired")
	}
	f, err := s.federations.Get(ctx, id)
	if err != nil {
		return domain.Federation{}, err
	}
	if f.Role != "follower" {
		return domain.Federation{}, fmt.Errorf("%w: resync runs on the mirror (follower) side", domain.ErrValidation)
	}
	if err := s.mirrors.RequestResync(ctx, id); err != nil {
		return domain.Federation{}, err
	}
	if s.relay != nil && f.Status == "active" && f.PausedAt == nil {
		s.relay.StopLink(f.VaultID, f.PeerURL)
		s.relay.StartLink(context.WithoutCancel(ctx), f.VaultID, f.PeerURL)
	}
	return f, nil
}

// ---- sever policy ----------------------------------------------------------------

// applySeverPolicy runs after a mirror link was severed by home.
func (s *Service) applySeverPolicy(f domain.Federation) {
	if !f.IsMirrorFollower() || f.SeverPolicy != SeverPurge || s.deleter == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := s.deleter.Delete(ctx, f.VaultID, uuid.Nil, "", ""); err != nil && !errors.Is(err, domain.ErrNotFound) {
			return
		}
		s.invalidateVault(f.VaultID)
		s.recordAudit(ctx, nil, uuid.Nil, domain.ActionMirrorPurged, "", "", map[string]any{
			"vault_id": f.VaultID,
			"peer_url": f.PeerURL,
		})
	}()
}

// ---- promotion (CLI only) ------------------------------------------------------------

// PromotionPlan is what `lumi-server mirror promote` carries over from
// home's last replicated control state.
type PromotionPlan struct {
	Name  string
	Roles []domain.Role
	// Members are local users (key "<username>@<this server>") with the
	// role name they hold at home.
	Members []PlannedMember
	// Dropped lists member keys that cannot be carried over (users of
	// other servers).
	Dropped []string
}

type PlannedMember struct {
	Username string
	Role     string
}

// PlanPromotion turns a replicated control document into local roles and
// members for baseURL (this server).
func PlanPromotion(stateJSON []byte, baseURL string) (PromotionPlan, error) {
	var doc ControlState
	if err := json.Unmarshal(stateJSON, &doc); err != nil {
		return PromotionPlan{}, fmt.Errorf("federation: control state: %w", err)
	}
	plan := PromotionPlan{Name: doc.Name}
	for _, r := range doc.Roles {
		caps := make(domain.CapabilitySet, len(r.Capabilities))
		for i, c := range r.Capabilities {
			caps[i] = domain.Capability(c)
		}
		plan.Roles = append(plan.Roles, domain.Role{Name: r.Name, Capabilities: caps, IsSeed: r.IsSeed})
	}
	self := normalizeServerURL(baseURL)
	for _, m := range doc.Members {
		at := strings.Index(m.Key, "@")
		if at > 0 && self != "" && normalizeServerURL(m.Key[at+1:]) == self {
			plan.Members = append(plan.Members, PlannedMember{Username: m.Key[:at], Role: m.Role})
			continue
		}
		plan.Dropped = append(plan.Dropped, m.Key)
	}
	sort.Strings(plan.Dropped)
	return plan, nil
}
