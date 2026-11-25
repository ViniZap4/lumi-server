// Package publish serves publish mirrors anonymously, phase M3
// (docs/SPEC-ESPELHO-SELADO.md §A15). Only a mirror server publishes, and
// only a book whose home owner consented (the link's publish policy) and
// whose mirror operator opted in (LUMI_PUBLISH_ENABLED plus a
// publish_settings row). Home already filters what reaches the mirror;
// this package filters again (defence in depth) and answers every refusal
// with the same 404, so the endpoints say nothing about notes, titles,
// paths, members or deletions outside the published scope.
//
//	GET /api/public/books/:slug           {name, notes:[{id,path,title,kind,updated_at}]}
//	GET /api/public/books/:slug/notes/:id {id,path,title,kind,updated_at,body}
//
// No cookies, no session, no audit per request (aggregate counters only).
// Cache-Control: public, max-age=60; X-Robots-Tag: noindex unless both the
// owner (publish.index) and the operator (robots=index) allow indexing.
// 60 requests/min per IP and 10 000/min per book; 429 with Retry-After.
// 410 Gone once the link is revoked/severed and the copy is not purged.
package publish

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/federation"
)

// ErrGone: the book was published but its link is no longer active.
var ErrGone = errors.New("publish: gone")

// maxListed caps the notes one book listing returns.
const maxListed = 5000

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidSlug reports whether s can be a publish slug.
func ValidSlug(s string) bool { return slugRe.MatchString(s) }

// BasePath is the base path of a slug.
func BasePath(slug string) string { return "/p/" + slug }

// Settings is the publish_settings surface (*pg.PublishStore).
type Settings interface {
	GetByBasePath(ctx context.Context, basePath string) (domain.PublishSetting, error)
}

// Links lists a vault's federation rows (*pg.FederationStore).
type Links interface {
	ListForVault(ctx context.Context, vaultID uuid.UUID) ([]domain.Federation, error)
}

// Vaults reads a vault row.
type Vaults interface {
	GetByID(ctx context.Context, id uuid.UUID) (domain.Vault, error)
}

// Notes reads note rows and their on-disk content (*notes.Service).
type Notes interface {
	List(ctx context.Context, vaultID uuid.UUID, limit, offset int) ([]domain.Note, error)
	GetContent(ctx context.Context, vaultID uuid.UUID, id string) (domain.Note, map[string]any, []byte, error)
}

// Service resolves published books.
type Service struct {
	Enabled  bool
	Settings Settings
	Links    Links
	Vaults   Vaults
	Notes    Notes
}

// Book is a published book's public face.
type Book struct {
	VaultID uuid.UUID
	Name    string
	Policy  federation.PublishPolicy
	Robots  string // the X-Robots-Tag value ("" = indexing allowed)
}

// NoteSummary is one listed note.
type NoteSummary struct {
	ID        string `json:"id"`
	Path      string `json:"path"`
	Title     string `json:"title"`
	Kind      string `json:"kind"`
	UpdatedAt string `json:"updated_at"`
}

// NoteBody is one published note.
type NoteBody struct {
	NoteSummary
	Body string `json:"body"`
}

// Resolve finds the published book behind slug. Every refusal is
// domain.ErrNotFound (or ErrGone for a revoked link), never a hint.
func (s *Service) Resolve(ctx context.Context, slug string) (Book, error) {
	if !s.Enabled || !ValidSlug(slug) {
		return Book{}, domain.ErrNotFound
	}
	set, err := s.Settings.GetByBasePath(ctx, BasePath(slug))
	if err != nil {
		return Book{}, domain.ErrNotFound
	}
	rows, err := s.Links.ListForVault(ctx, set.VaultID)
	if err != nil {
		return Book{}, fmt.Errorf("publish: links: %w", err)
	}
	var link *domain.Federation
	for i := range rows {
		if rows[i].Role == "follower" && rows[i].Mode == federation.ModeMirror {
			link = &rows[i]
			break
		}
	}
	if link == nil || link.PromotedAt != nil {
		return Book{}, domain.ErrNotFound
	}
	policy := federation.UnmarshalPublish(link.Publish)
	if policy == nil {
		// Not a publish mirror (the owner never consented): an operator
		// row alone publishes nothing.
		return Book{}, domain.ErrNotFound
	}
	if link.Status != "active" {
		return Book{}, ErrGone
	}
	v, err := s.Vaults.GetByID(ctx, set.VaultID)
	if err != nil {
		return Book{}, domain.ErrNotFound
	}
	robots := "noindex, nofollow"
	if policy.Index && set.Robots == "index" {
		robots = ""
	}
	return Book{VaultID: v.ID, Name: v.Name, Policy: *policy, Robots: robots}, nil
}

// inScope re-checks the scope on the mirror (home filtered already).
func inScope(p federation.PublishPolicy, n domain.Note, front map[string]any) bool {
	if p.Scope == federation.PublishScopeFlagged {
		v, ok := front["publish"].(bool)
		return ok && v && !domain.IsCanvasPath(n.Path)
	}
	return p.Match(n.Path, nil)
}

func summary(n domain.Note) NoteSummary {
	kind := "markdown"
	if domain.IsCanvasPath(n.Path) {
		kind = "canvas"
	}
	return NoteSummary{ID: n.ID, Path: n.Path, Title: n.Title, Kind: kind, UpdatedAt: n.UpdatedAt.UTC().Format(time.RFC3339)}
}

// List returns the book's published notes, sorted by path.
func (s *Service) List(ctx context.Context, b Book) ([]NoteSummary, error) {
	const page = 500
	out := []NoteSummary{}
	for offset := 0; len(out) < maxListed; offset += page {
		batch, err := s.Notes.List(ctx, b.VaultID, page, offset)
		if err != nil {
			return nil, err
		}
		for _, n := range batch {
			var front map[string]any
			if b.Policy.Scope == federation.PublishScopeFlagged {
				_, f, _, err := s.Notes.GetContent(ctx, b.VaultID, n.ID)
				if err != nil {
					continue // no file yet: not served
				}
				front = f
			}
			if inScope(b.Policy, n, front) {
				out = append(out, summary(n))
			}
		}
		if len(batch) < page {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	if len(out) > maxListed {
		out = out[:maxListed]
	}
	return out, nil
}

// Note returns one published note's body (raw markdown without the
// frontmatter, or the canvas JSON).
func (s *Service) Note(ctx context.Context, b Book, noteID string) (NoteBody, error) {
	if noteID == "" || len(noteID) > 256 {
		return NoteBody{}, domain.ErrNotFound
	}
	n, front, body, err := s.Notes.GetContent(ctx, b.VaultID, noteID)
	if err != nil || !inScope(b.Policy, n, front) {
		return NoteBody{}, domain.ErrNotFound
	}
	return NoteBody{NoteSummary: summary(n), Body: string(body)}, nil
}
