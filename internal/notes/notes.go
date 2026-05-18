// Package notes implements note CRUD over the per-vault filesystem and
// Postgres metadata mirror. Bodies live on disk under
// <root>/<vault-slug>/<note-id>.md as markdown with YAML frontmatter;
// Postgres stores only path/title/timestamps for cheap list/search.
//
// CRDT live-collab (Yjs sync, snapshot/diff endpoints) is Phase 2.2; this
// file ships the pure-REST CRUD surface only so apple-client and tui-client
// v2 can browse, create, edit and delete notes against a v2 server.
package notes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/audit"
	"github.com/ViniZap4/lumi-server/internal/capguard"
	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/storage/fs"
)

// ---- Dependencies ----------------------------------------------------------

// NoteRepo is the persistence boundary for note metadata.
type NoteRepo interface {
	Upsert(ctx context.Context, n domain.Note) error
	Get(ctx context.Context, vaultID uuid.UUID, id string) (domain.Note, error)
	GetByPath(ctx context.Context, vaultID uuid.UUID, path string) (domain.Note, error)
	ListForVault(ctx context.Context, vaultID uuid.UUID, limit, offset int) ([]domain.Note, error)
	Delete(ctx context.Context, vaultID uuid.UUID, id string) error
}

// VaultLookup resolves a vault UUID to the row so the service can derive
// the on-disk slug for fs.Manager calls.
type VaultLookup interface {
	GetByID(ctx context.Context, id uuid.UUID) (domain.Vault, error)
}

// ---- Service ---------------------------------------------------------------

// Service orchestrates Postgres metadata, on-disk markdown bodies, and audit
// recording. Methods are non-transactional in Phase 2.1; FS errors after a
// pg row write are best-effort rolled back. SPEC tightens transactional
// guarantees in Phase 3.
type Service struct {
	notes    NoteRepo
	vaults   VaultLookup
	fs       *fs.Manager
	audit    audit.Recorder
	resolver capguard.Resolver
	now      func() time.Time
}

func NewService(
	notes NoteRepo,
	vaults VaultLookup,
	fsMgr *fs.Manager,
	a audit.Recorder,
	resolver capguard.Resolver,
) *Service {
	if notes == nil || vaults == nil || fsMgr == nil || resolver == nil {
		panic("notes.NewService: missing dependency")
	}
	if a == nil {
		a = audit.Noop{}
	}
	return &Service{
		notes:    notes,
		vaults:   vaults,
		fs:       fsMgr,
		audit:    a,
		resolver: resolver,
		now:      time.Now,
	}
}

// ---- Slugify ---------------------------------------------------------------

// Note IDs follow the same convention as v1 TUI/server: lowercase ASCII,
// non-alphanumeric folded to hyphens, collapsed. Reserved for the filename
// stem only — directory separators are forbidden.
var slugFoldRE = regexp.MustCompile(`[^a-z0-9]+`)

const maxNoteIDLen = 80

func slugifyTitle(title string) string {
	s := strings.ToLower(strings.TrimSpace(title))
	s = slugFoldRE.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > maxNoteIDLen {
		s = strings.TrimRight(s[:maxNoteIDLen], "-")
	}
	if s == "" {
		return "untitled"
	}
	return s
}

// ---- Inputs ----------------------------------------------------------------

type CreateInput struct {
	Title string
	Body  string
	Tags  []string
	Actor uuid.UUID
	IP    string
	UA    string
}

type UpdateInput struct {
	// Pointers so callers can distinguish "unset" from "empty".
	Title *string
	Body  *string
	Path  *string
	Tags  *[]string
	Actor uuid.UUID
	IP    string
	UA    string
}

// ---- Service: Create -------------------------------------------------------

// Create slugifies Title into a unique note ID inside the vault, writes the
// markdown file with frontmatter, mirrors metadata to Postgres, and audits.
//
// Conflict policy: if the derived ID is already taken, an integer suffix is
// appended (`hello`, `hello-2`, `hello-3`, …) until a free slot is found.
// Phase 2.1 limit: 50 attempts before bailing with ErrConflict.
func (s *Service) Create(ctx context.Context, vaultID uuid.UUID, in CreateInput) (domain.Note, error) {
	title := strings.TrimSpace(in.Title)
	if title == "" {
		return domain.Note{}, fmt.Errorf("%w: title is required", domain.ErrValidation)
	}
	v, err := s.vaults.GetByID(ctx, vaultID)
	if err != nil {
		return domain.Note{}, err
	}

	base := slugifyTitle(title)
	id, err := s.allocateNoteID(ctx, vaultID, base)
	if err != nil {
		return domain.Note{}, err
	}
	relPath := id + ".md"
	now := s.now().UTC()

	front := map[string]any{
		"id":         id,
		"title":      title,
		"created_at": now.Format(time.RFC3339),
		"updated_at": now.Format(time.RFC3339),
	}
	if len(in.Tags) > 0 {
		front["tags"] = in.Tags
	}
	if err := s.fs.WriteNote(v.Slug, relPath, front, []byte(in.Body)); err != nil {
		return domain.Note{}, fmt.Errorf("write note: %w", err)
	}

	note := domain.Note{
		ID:        id,
		VaultID:   vaultID,
		Path:      relPath,
		Title:     title,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := s.notes.Upsert(ctx, note); err != nil {
		// Roll back the on-disk file so we don't leave orphans.
		_ = s.fs.DeleteNote(v.Slug, relPath)
		return domain.Note{}, err
	}

	s.recordAudit(ctx, in.Actor, vaultID, domain.ActionNoteCreate, in.IP, in.UA, map[string]any{
		"note_id": id,
		"path":    relPath,
		"title":   title,
	})
	return note, nil
}

func (s *Service) allocateNoteID(ctx context.Context, vaultID uuid.UUID, base string) (string, error) {
	const maxAttempts = 50
	for i := 0; i < maxAttempts; i++ {
		candidate := base
		if i > 0 {
			candidate = fmt.Sprintf("%s-%d", base, i+1)
		}
		if _, err := s.notes.Get(ctx, vaultID, candidate); err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return candidate, nil
			}
			return "", err
		}
	}
	return "", fmt.Errorf("%w: too many ID collisions for %q", domain.ErrConflict, base)
}

// ---- Service: Read ---------------------------------------------------------

func (s *Service) Get(ctx context.Context, vaultID uuid.UUID, id string) (domain.Note, error) {
	return s.notes.Get(ctx, vaultID, id)
}

// GetContent returns the parsed frontmatter and the raw markdown body bytes.
// Frontmatter values are passed through as-is; the handler converts them to
// JSON-friendly types.
func (s *Service) GetContent(ctx context.Context, vaultID uuid.UUID, id string) (domain.Note, map[string]any, []byte, error) {
	n, err := s.notes.Get(ctx, vaultID, id)
	if err != nil {
		return domain.Note{}, nil, nil, err
	}
	v, err := s.vaults.GetByID(ctx, vaultID)
	if err != nil {
		return domain.Note{}, nil, nil, err
	}
	front, body, err := s.fs.ReadNote(v.Slug, n.Path)
	if err != nil {
		return domain.Note{}, nil, nil, err
	}
	return n, front, body, nil
}

func (s *Service) List(ctx context.Context, vaultID uuid.UUID, limit, offset int) ([]domain.Note, error) {
	return s.notes.ListForVault(ctx, vaultID, limit, offset)
}

// ---- Service: Update -------------------------------------------------------

// Update applies any of {title, body, tags, path} that the caller set. Path
// changes trigger an FS rename; title/body/tags rewrite the file with new
// frontmatter. Audits at most one action per call:
//   - ActionNoteMove if path changed,
//   - else ActionNoteEdit if anything else changed,
//   - else nothing (no-op call).
func (s *Service) Update(ctx context.Context, vaultID uuid.UUID, id string, in UpdateInput) (domain.Note, error) {
	n, err := s.notes.Get(ctx, vaultID, id)
	if err != nil {
		return domain.Note{}, err
	}
	v, err := s.vaults.GetByID(ctx, vaultID)
	if err != nil {
		return domain.Note{}, err
	}

	moved := false
	newPath := n.Path
	if in.Path != nil {
		cleaned, err := validateNoteRelPath(*in.Path)
		if err != nil {
			return domain.Note{}, err
		}
		if cleaned != n.Path {
			if _, err := s.notes.GetByPath(ctx, vaultID, cleaned); err == nil {
				return domain.Note{}, fmt.Errorf("%w: path %q already exists", domain.ErrConflict, cleaned)
			} else if !errors.Is(err, domain.ErrNotFound) {
				return domain.Note{}, err
			}
			if err := s.fs.MoveNote(v.Slug, n.Path, cleaned); err != nil {
				return domain.Note{}, err
			}
			newPath = cleaned
			moved = true
		}
	}

	// Re-read so we operate against the canonical on-disk frontmatter
	// (which may carry fields we never modelled — unknownLines style).
	front, body, err := s.fs.ReadNote(v.Slug, newPath)
	if err != nil {
		return domain.Note{}, err
	}

	edited := false
	now := s.now().UTC()
	newTitle := n.Title
	if in.Title != nil {
		t := strings.TrimSpace(*in.Title)
		if t == "" {
			return domain.Note{}, fmt.Errorf("%w: title cannot be empty", domain.ErrValidation)
		}
		if t != n.Title {
			front["title"] = t
			newTitle = t
			edited = true
		}
	}
	if in.Tags != nil {
		front["tags"] = *in.Tags
		edited = true
	}
	if in.Body != nil {
		body = []byte(*in.Body)
		edited = true
	}
	if edited {
		front["updated_at"] = now.Format(time.RFC3339)
		if _, ok := front["id"]; !ok {
			front["id"] = id
		}
		if err := s.fs.WriteNote(v.Slug, newPath, front, body); err != nil {
			return domain.Note{}, err
		}
	}

	updated := domain.Note{
		ID:        id,
		VaultID:   vaultID,
		Path:      newPath,
		Title:     newTitle,
		CreatedAt: n.CreatedAt,
		UpdatedAt: now,
	}
	if !edited && !moved {
		return n, nil
	}
	if err := s.notes.Upsert(ctx, updated); err != nil {
		return domain.Note{}, err
	}

	switch {
	case moved:
		s.recordAudit(ctx, in.Actor, vaultID, domain.ActionNoteMove, in.IP, in.UA, map[string]any{
			"note_id":  id,
			"old_path": n.Path,
			"new_path": newPath,
		})
	case edited:
		s.recordAudit(ctx, in.Actor, vaultID, domain.ActionNoteEdit, in.IP, in.UA, map[string]any{
			"note_id": id,
			"path":    newPath,
		})
	}
	return updated, nil
}

// validateNoteRelPath rejects absolute paths, parent traversals, and any
// path that does not end in `.md`. fs.SafeJoin enforces the same plus
// symlink-escape — this check exists to fail early with a friendlier error.
func validateNoteRelPath(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("%w: path is required", domain.ErrValidation)
	}
	cleaned := path.Clean(s)
	if cleaned == "." || strings.HasPrefix(cleaned, "/") || strings.HasPrefix(cleaned, "..") {
		return "", fmt.Errorf("%w: path %q escapes vault", domain.ErrValidation, raw)
	}
	if !strings.HasSuffix(cleaned, ".md") {
		return "", fmt.Errorf("%w: path must end with .md", domain.ErrValidation)
	}
	return cleaned, nil
}

// ---- Service: Delete -------------------------------------------------------

func (s *Service) Delete(ctx context.Context, vaultID uuid.UUID, id string, actor uuid.UUID, ip, ua string) error {
	n, err := s.notes.Get(ctx, vaultID, id)
	if err != nil {
		return err
	}
	v, err := s.vaults.GetByID(ctx, vaultID)
	if err != nil {
		return err
	}
	if err := s.notes.Delete(ctx, vaultID, id); err != nil {
		return err
	}
	if err := s.fs.DeleteNote(v.Slug, n.Path); err != nil && !errors.Is(err, domain.ErrNotFound) {
		// pg row is already gone; surface but don't fail the request.
		s.recordAudit(ctx, actor, vaultID, domain.ActionNoteDelete, ip, ua, map[string]any{
			"note_id":  id,
			"path":     n.Path,
			"fs_error": err.Error(),
		})
		return nil
	}
	s.recordAudit(ctx, actor, vaultID, domain.ActionNoteDelete, ip, ua, map[string]any{
		"note_id": id,
		"path":    n.Path,
	})
	return nil
}

// ---- Audit -----------------------------------------------------------------

func (s *Service) recordAudit(ctx context.Context, userID, vaultID uuid.UUID, action, ip, ua string, payload map[string]any) {
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{}`)
	}
	entry := domain.AuditEntry{Action: action, Payload: body}
	if userID != uuid.Nil {
		uid := userID
		entry.UserID = &uid
	}
	if vaultID != uuid.Nil {
		vid := vaultID
		entry.VaultID = &vid
	}
	if ip != "" {
		entry.IP = &ip
	}
	if ua != "" {
		entry.UserAgent = &ua
	}
	_ = s.audit.Record(ctx, entry)
}

// ---- Handlers --------------------------------------------------------------

type Handlers struct {
	svc *Service
}

func NewHandlers(svc *Service) *Handlers {
	return &Handlers{svc: svc}
}

// Pagination matches the audit endpoint's contract so clients can reuse the
// same envelope.
const (
	defaultLimit = 50
	maxLimit     = 200
)

func (h *Handlers) Register(r fiber.Router) {
	resolver := h.svc.resolver
	r.Get("/vaults/:vault/notes",
		capguard.RequireCapability(resolver, domain.CapNoteRead),
		h.list,
	)
	r.Post("/vaults/:vault/notes",
		capguard.RequireCapability(resolver, domain.CapNoteCreate),
		h.create,
	)
	r.Get("/vaults/:vault/notes/:id",
		capguard.RequireCapability(resolver, domain.CapNoteRead),
		h.get,
	)
	r.Get("/vaults/:vault/notes/:id/content",
		capguard.RequireCapability(resolver, domain.CapNoteRead),
		h.getContent,
	)
	r.Patch("/vaults/:vault/notes/:id",
		// PATCH may rename/move or edit content; require the broader of the
		// two upfront, then re-check inside the handler when a move is
		// requested. Phase 2.1 simplification: any successful PATCH proves
		// note.edit; move-only callers without note.edit will be told to
		// add it, accepted as a known limitation.
		capguard.RequireCapability(resolver, domain.CapNoteEdit),
		h.update,
	)
	r.Delete("/vaults/:vault/notes/:id",
		capguard.RequireCapability(resolver, domain.CapNoteDelete),
		h.delete,
	)
}

type noteDTO struct {
	ID        string `json:"id"`
	VaultID   string `json:"vault_id"`
	Path      string `json:"path"`
	Title     string `json:"title"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

func toDTO(n domain.Note) noteDTO {
	return noteDTO{
		ID:        n.ID,
		VaultID:   n.VaultID.String(),
		Path:      n.Path,
		Title:     n.Title,
		CreatedAt: n.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt: n.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

// noteIDParam extracts the `:id` URL param with a basic sanity check. The
// param is the slugified stem, not a UUID, so we just reject empties and
// path-separators (defence in depth — capguard.WithVaultID has already
// resolved the vault UUID).
func noteIDParam(c *fiber.Ctx) (string, error) {
	raw := strings.TrimSpace(c.Params("id"))
	if raw == "" || strings.ContainsAny(raw, "/\\") {
		_ = c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_note_id"})
		return "", domain.ErrValidation
	}
	return raw, nil
}

func parsePagination(c *fiber.Ctx) (limit, offset int) {
	limit = defaultLimit
	if raw := c.Query("limit"); raw != "" {
		if n, err := atoiPos(raw); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	if raw := c.Query("offset"); raw != "" {
		if n, err := atoiPos(raw); err == nil && n >= 0 {
			offset = n
		}
	}
	return
}

func atoiPos(s string) (int, error) {
	var n int
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("not a positive integer")
		}
		n = n*10 + int(r-'0')
		if n > 1<<30 {
			return 0, fmt.Errorf("overflow")
		}
	}
	return n, nil
}

// list — GET /api/vaults/:vault/notes
func (h *Handlers) list(c *fiber.Ctx) error {
	vaultID, err := capguard.WithVaultID(c)
	if err != nil {
		return nil
	}
	limit, offset := parsePagination(c)
	notes, err := h.svc.List(c.UserContext(), vaultID, limit, offset)
	if err != nil {
		return mapErr(c, err)
	}
	out := make([]noteDTO, 0, len(notes))
	for _, n := range notes {
		out = append(out, toDTO(n))
	}
	return c.JSON(fiber.Map{
		"notes":  out,
		"limit":  limit,
		"offset": offset,
	})
}

type createReq struct {
	Title string   `json:"title"`
	Body  string   `json:"body"`
	Tags  []string `json:"tags,omitempty"`
}

// create — POST /api/vaults/:vault/notes
func (h *Handlers) create(c *fiber.Ctx) error {
	vaultID, err := capguard.WithVaultID(c)
	if err != nil {
		return nil
	}
	var req createReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_body"})
	}
	uid, _ := capguard.UserIDFrom(c)
	n, err := h.svc.Create(c.UserContext(), vaultID, CreateInput{
		Title: req.Title,
		Body:  req.Body,
		Tags:  req.Tags,
		Actor: uid,
		IP:    c.IP(),
		UA:    string(c.Request().Header.UserAgent()),
	})
	if err != nil {
		return mapErr(c, err)
	}
	return c.Status(http.StatusCreated).JSON(toDTO(n))
}

// get — GET /api/vaults/:vault/notes/:id  (metadata only)
func (h *Handlers) get(c *fiber.Ctx) error {
	vaultID, err := capguard.WithVaultID(c)
	if err != nil {
		return nil
	}
	id, err := noteIDParam(c)
	if err != nil {
		return nil
	}
	n, err := h.svc.Get(c.UserContext(), vaultID, id)
	if err != nil {
		return mapErr(c, err)
	}
	return c.JSON(toDTO(n))
}

// getContent — GET /api/vaults/:vault/notes/:id/content
//
// Returns the parsed frontmatter plus the raw body so clients can render or
// re-edit without having to re-parse the YAML themselves. Body is exposed
// as a string (UTF-8 markdown); we do not attempt to detect binary content
// because the file is constrained to be markdown by convention.
func (h *Handlers) getContent(c *fiber.Ctx) error {
	vaultID, err := capguard.WithVaultID(c)
	if err != nil {
		return nil
	}
	id, err := noteIDParam(c)
	if err != nil {
		return nil
	}
	n, front, body, err := h.svc.GetContent(c.UserContext(), vaultID, id)
	if err != nil {
		return mapErr(c, err)
	}
	return c.JSON(fiber.Map{
		"id":          n.ID,
		"vault_id":    n.VaultID.String(),
		"path":        n.Path,
		"frontmatter": yamlToJSON(front),
		"body":        string(body),
	})
}

type updateReq struct {
	Title *string   `json:"title,omitempty"`
	Body  *string   `json:"body,omitempty"`
	Path  *string   `json:"path,omitempty"`
	Tags  *[]string `json:"tags,omitempty"`
}

// update — PATCH /api/vaults/:vault/notes/:id
func (h *Handlers) update(c *fiber.Ctx) error {
	vaultID, err := capguard.WithVaultID(c)
	if err != nil {
		return nil
	}
	id, err := noteIDParam(c)
	if err != nil {
		return nil
	}
	var req updateReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_body"})
	}
	if req.Path != nil {
		if err := capguard.Require(c, h.svc.resolver, vaultID, domain.CapNoteMove); err != nil {
			return nil
		}
	}
	uid, _ := capguard.UserIDFrom(c)
	n, err := h.svc.Update(c.UserContext(), vaultID, id, UpdateInput{
		Title: req.Title,
		Body:  req.Body,
		Path:  req.Path,
		Tags:  req.Tags,
		Actor: uid,
		IP:    c.IP(),
		UA:    string(c.Request().Header.UserAgent()),
	})
	if err != nil {
		return mapErr(c, err)
	}
	return c.JSON(toDTO(n))
}

// delete — DELETE /api/vaults/:vault/notes/:id
func (h *Handlers) delete(c *fiber.Ctx) error {
	vaultID, err := capguard.WithVaultID(c)
	if err != nil {
		return nil
	}
	id, err := noteIDParam(c)
	if err != nil {
		return nil
	}
	uid, _ := capguard.UserIDFrom(c)
	if err := h.svc.Delete(c.UserContext(), vaultID, id, uid, c.IP(), string(c.Request().Header.UserAgent())); err != nil {
		return mapErr(c, err)
	}
	return c.SendStatus(http.StatusNoContent)
}

// yamlToJSON walks a value tree produced by gopkg.in/yaml.v3's Unmarshal
// into map[string]any and converts the yaml-specific map keys
// (map[any]any) into JSON-compatible map[string]any so encoding/json can
// emit them without panicking.
func yamlToJSON(v any) any {
	switch t := v.(type) {
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, v := range t {
			out[fmt.Sprint(k)] = yamlToJSON(v)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, v := range t {
			out[k] = yamlToJSON(v)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, v := range t {
			out[i] = yamlToJSON(v)
		}
		return out
	default:
		return v
	}
}

func mapErr(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "not_found"})
	case errors.Is(err, domain.ErrValidation):
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "validation", "detail": err.Error()})
	case errors.Is(err, domain.ErrConflict):
		return c.Status(http.StatusConflict).JSON(fiber.Map{"error": "conflict", "detail": err.Error()})
	case errors.Is(err, domain.ErrPathEscape):
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_path"})
	case errors.Is(err, domain.ErrUnauthorized):
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	case errors.Is(err, domain.ErrForbidden), errors.Is(err, domain.ErrCapabilityMissing):
		return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
	default:
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "internal"})
	}
}
