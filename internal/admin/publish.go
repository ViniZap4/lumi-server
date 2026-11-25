// Publish mirrors, operator side (docs/SPEC-ESPELHO-SELADO.md §A15.1):
// `lumi-server publish enable|disable|list`. The home owner consents in
// the invite (the link's publish policy); the mirror operator opts in
// here, per vault, with a base path /p/<slug>. LUMI_PUBLISH_ENABLED must
// also be true for the public endpoints to answer.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// Publish audit actions.
const (
	ActionPublishEnable  = domain.ActionPublishEnable
	ActionPublishDisable = domain.ActionPublishDisable
)

// PublishStore is the publish_settings surface (*pg.PublishStore).
type PublishStore interface {
	Upsert(ctx context.Context, p domain.PublishSetting, e domain.AuditEntry) error
	Delete(ctx context.Context, vaultID uuid.UUID, e domain.AuditEntry) error
	List(ctx context.Context) ([]domain.PublishSetting, error)
}

var publishSlugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Publication is one published book.
type Publication struct {
	Vault     Vault
	BasePath  string
	Robots    string
	EnabledAt time.Time
	// Scope is the owner's scope ("flagged", "all", "folder:<prefix>").
	Scope string
	// Index: the owner allows indexing (the operator's Robots too).
	Index bool
	// Status of the mirror link ("active", "severed", ...).
	Status string
}

type publishPolicy struct {
	Allowed bool   `json:"allowed"`
	Scope   string `json:"scope"`
	Index   bool   `json:"index"`
}

// publishLink returns the vault's mirror link with its owner consent.
func (s *Service) publishLink(ctx context.Context, vaultID uuid.UUID) (Federation, publishPolicy, error) {
	feds, _, err := s.Store.ListFederations(ctx, FederationFilter{VaultID: &vaultID, Mode: "mirror"}, nil, 50)
	if err != nil {
		return Federation{}, publishPolicy{}, err
	}
	for _, f := range feds {
		if f.Role != "follower" || f.PromotedAt != nil {
			continue
		}
		var p publishPolicy
		if len(f.Publish) == 0 || json.Unmarshal(f.Publish, &p) != nil || !p.Allowed {
			return f, publishPolicy{}, invalid("vault", "the home owner did not consent to publish this mirror (invite it with publish)")
		}
		return f, p, nil
	}
	return Federation{}, publishPolicy{}, invalid("vault", "not a mirror on this server: only publish mirrors can be published")
}

// EnablePublish publishes the mirror vaultRef at /p/<slug>. robots is
// "noindex" (default) or "index" (indexing also needs the owner's
// consent).
func (s *Service) EnablePublish(ctx context.Context, a Actor, vaultRef, slug, robots string) (Publication, error) {
	if s.Publish == nil {
		return Publication{}, errors.New("admin: publish store not wired")
	}
	if !publishSlugRe.MatchString(slug) {
		return Publication{}, invalid("slug", "must be 1-63 of a-z, 0-9 and '-', starting with a letter or digit")
	}
	if robots == "" {
		robots = "noindex"
	}
	if robots != "noindex" && robots != "index" {
		return Publication{}, invalid("robots", "must be noindex or index")
	}
	v, err := s.ResolveVault(ctx, vaultRef)
	if err != nil {
		return Publication{}, err
	}
	f, p, err := s.publishLink(ctx, v.ID)
	if err != nil {
		return Publication{}, err
	}
	set := domain.PublishSetting{VaultID: v.ID, BasePath: "/p/" + slug, Robots: robots, EnabledAt: s.clock().UTC()}
	e := s.entry(a, ActionPublishEnable, nil, &v.ID, map[string]any{
		"base_path": set.BasePath, "robots": robots, "scope": p.Scope, "peer_url": f.PeerURL,
	})
	if err := s.Publish.Upsert(ctx, set, e); err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return Publication{}, fmt.Errorf("%w: base path %s is taken", domain.ErrConflict, set.BasePath)
		}
		return Publication{}, err
	}
	s.logAction(a, ActionPublishEnable).Str("vault", v.Slug).Str("base_path", set.BasePath).Msg("admin action")
	return Publication{Vault: v, BasePath: set.BasePath, Robots: robots, EnabledAt: set.EnabledAt, Scope: p.Scope, Index: p.Index, Status: f.Status}, nil
}

// DisablePublish stops serving vaultRef anonymously (the mirror stays).
func (s *Service) DisablePublish(ctx context.Context, a Actor, vaultRef string) error {
	if s.Publish == nil {
		return errors.New("admin: publish store not wired")
	}
	v, err := s.ResolveVault(ctx, vaultRef)
	if err != nil {
		return err
	}
	if err := s.Publish.Delete(ctx, v.ID, s.entry(a, ActionPublishDisable, nil, &v.ID, nil)); err != nil {
		return err
	}
	s.logAction(a, ActionPublishDisable).Str("vault", v.Slug).Msg("admin action")
	return nil
}

// ListPublish lists the published books.
func (s *Service) ListPublish(ctx context.Context) ([]Publication, error) {
	if s.Publish == nil {
		return nil, errors.New("admin: publish store not wired")
	}
	rows, err := s.Publish.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Publication, 0, len(rows))
	for _, r := range rows {
		pub := Publication{BasePath: r.BasePath, Robots: r.Robots, EnabledAt: r.EnabledAt}
		if v, err := s.Store.GetVault(ctx, r.VaultID); err == nil {
			pub.Vault = v
		} else {
			pub.Vault = Vault{ID: r.VaultID}
		}
		if f, p, err := s.publishLink(ctx, r.VaultID); err == nil {
			pub.Scope, pub.Index, pub.Status = p.Scope, p.Index, f.Status
		} else {
			pub.Status = "not_publishable"
		}
		out = append(out, pub)
	}
	return out, nil
}
