package vaults

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// Feed / books support (SPEC-LIVROS §3.5): each vault is reported with the
// caller's role, can_edit, this server's head seq and federation info so a
// client logged into several federated servers can deduplicate books.

// HeadReader returns current vault heads (pg.NoteStore.Heads).
type HeadReader interface {
	Heads(ctx context.Context, vaultIDs []uuid.UUID) (map[uuid.UUID]int64, error)
}

// FederationLister lists a vault's federation links (pg.FederationStore).
type FederationLister interface {
	ListForVault(ctx context.Context, vaultID uuid.UUID) ([]domain.Federation, error)
}

// FeedNotifier hears vault lifecycle changes for the account feed
// (implemented by *feed.Broker). Must not block.
type FeedNotifier interface {
	VaultUpdated(vaultID uuid.UUID, fields ...string)
	VaultDeleted(vaultID uuid.UUID)
	AccessChanged(vaultID uuid.UUID, userIDs ...uuid.UUID)
}

// SetFeedDeps wires head/federation lookups and the feed notifier. baseURL
// is this server's public URL (home_url for vaults this server homes).
// Any argument may be nil.
func (s *Service) SetFeedDeps(heads HeadReader, feds FederationLister, baseURL string, n FeedNotifier) {
	s.heads = heads
	s.feds = feds
	s.baseURL = baseURL
	s.feed = n
}

// FederationInfo is the federation summary of one vault on this server.
// Role is nil when the vault is not federated.
type FederationInfo struct {
	// Role is "home", "follower" (a replica), "mirror" (a read-only
	// mirror on this server, docs/SPEC-ESPELHO-SELADO.md §A2) or null.
	Role    *string `json:"role"`
	HomeURL *string `json:"home_url"` // origin server URL, null when unknown/not federated
	Status  *string `json:"status"`   // "active" | "revoked" | "severed" | null
	// Mode of this server's follower link: "replica" | "mirror" | null.
	Mode *string `json:"mode"`
}

// IsMirror reports whether the vault is a read-only mirror here.
func (f FederationInfo) IsMirror() bool { return f.Role != nil && *f.Role == "mirror" }

// View is a vault as seen by one user.
type View struct {
	Vault      domain.Vault
	Role       domain.Role
	Head       int64
	Federation FederationInfo
}

// CanRead reports note.read (the feed's capability filter).
func (v View) CanRead() bool { return v.Role.Capabilities.Has(domain.CapNoteRead) }

// CanEdit reports note.edit.
func (v View) CanEdit() bool { return v.Role.Capabilities.Has(domain.CapNoteEdit) }

// ListViews returns every vault the user is a member of with role, head
// and federation info. Vaults where the federation-aware resolver denies
// membership (e.g. a follower replica whose control state dropped the
// user) are omitted.
func (s *Service) ListViews(ctx context.Context, userID uuid.UUID) ([]View, error) {
	vs, err := s.repo.ListForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]View, 0, len(vs))
	ids := make([]uuid.UUID, 0, len(vs))
	for _, v := range vs {
		role, err := s.resolver.RoleForUser(ctx, v.ID, userID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				continue
			}
			return nil, err
		}
		fed, err := s.federationInfo(ctx, v.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, View{Vault: v, Role: role, Federation: fed})
		ids = append(ids, v.ID)
	}
	if s.heads != nil && len(ids) > 0 {
		heads, err := s.heads.Heads(ctx, ids)
		if err != nil {
			return nil, err
		}
		for i := range out {
			out[i].Head = heads[out[i].Vault.ID]
		}
	}
	return out, nil
}

// GetView returns one vault as seen by userID; domain.ErrNotFound when the
// user holds no role in it (or it does not exist).
func (s *Service) GetView(ctx context.Context, userID, vaultID uuid.UUID) (View, error) {
	role, err := s.resolver.RoleForUser(ctx, vaultID, userID)
	if err != nil {
		return View{}, err
	}
	v, err := s.repo.GetByID(ctx, vaultID)
	if err != nil {
		return View{}, err
	}
	fed, err := s.federationInfo(ctx, vaultID)
	if err != nil {
		return View{}, err
	}
	view := View{Vault: v, Role: role, Federation: fed}
	if s.heads != nil {
		heads, err := s.heads.Heads(ctx, []uuid.UUID{vaultID})
		if err != nil {
			return View{}, err
		}
		view.Head = heads[vaultID]
	}
	return view, nil
}

func (s *Service) federationInfo(ctx context.Context, vaultID uuid.UUID) (FederationInfo, error) {
	if s.feds == nil {
		return FederationInfo{}, nil
	}
	rows, err := s.feds.ListForVault(ctx, vaultID)
	if err != nil {
		return FederationInfo{}, err
	}
	return deriveFederationInfo(rows, s.baseURL), nil
}

// deriveFederationInfo: a follower link makes this server a follower
// (home_url = that peer; an active link wins over revoked/severed ones);
// otherwise home links make it the home (home_url = this server, status
// active if any link is). No links → not federated.
func deriveFederationInfo(rows []domain.Federation, baseURL string) FederationInfo {
	str := func(s string) *string { return &s }
	var follower *domain.Federation
	var homeStatus string
	for i := range rows {
		r := &rows[i]
		switch r.Role {
		case "follower":
			if follower == nil || (follower.Status != "active" && r.Status == "active") {
				follower = r
			}
		case "home":
			if homeStatus != "active" {
				homeStatus = r.Status
			}
		}
	}
	switch {
	case follower != nil:
		role, mode := "follower", "replica"
		if follower.Mode == "mirror" {
			mode = "mirror"
			// A promoted mirror is an independent home now.
			if follower.PromotedAt == nil {
				role = "mirror"
			}
		}
		return FederationInfo{Role: str(role), HomeURL: str(follower.PeerURL), Status: str(follower.Status), Mode: str(mode)}
	case homeStatus != "":
		info := FederationInfo{Role: str("home"), Status: str(homeStatus)}
		if baseURL != "" {
			info.HomeURL = str(baseURL)
		}
		return info
	}
	return FederationInfo{}
}

// ---- notifier helpers ---------------------------------------------------------

func (s *Service) feedUpdated(vaultID uuid.UUID, fields ...string) {
	if s.feed != nil {
		s.feed.VaultUpdated(vaultID, fields...)
	}
}

func (s *Service) feedDeleted(vaultID uuid.UUID) {
	if s.feed != nil {
		s.feed.VaultDeleted(vaultID)
	}
}

func (s *Service) feedAccess(vaultID uuid.UUID, userIDs ...uuid.UUID) {
	if s.feed != nil {
		s.feed.AccessChanged(vaultID, userIDs...)
	}
}
