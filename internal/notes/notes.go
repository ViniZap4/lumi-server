// Package notes implements note CRUD over the per-vault filesystem and
// Postgres metadata mirror. Bodies live on disk under
// <root>/<vault-slug>/<note-id>.md as markdown with YAML frontmatter;
// Postgres stores only path/title/timestamps for cheap list/search.
//
// Phase 2.2 adds the CRDT shadow: every body change also runs through a
// yrs document so concurrent writers can be merged. The filesystem
// remains the source of truth for what's on disk; the CRDT is the
// operational projection.
package notes

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/audit"
	"github.com/ViniZap4/lumi-server/internal/capguard"
	"github.com/ViniZap4/lumi-server/internal/crdt"
	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/storage/fs"
	"github.com/ViniZap4/lumi-server/internal/wsync"
)

// ---- Dependencies ----------------------------------------------------------

// NoteRepo is the persistence boundary for note metadata.
//
// Every write bumps the vault's change sequence in the same transaction
// and returns the new seq (SPEC-LIVROS §3.4): Upsert stamps it on the row,
// Delete on a tombstone, TouchContent on a coalesced content edit.
type NoteRepo interface {
	Upsert(ctx context.Context, n domain.Note) (int64, error)
	Get(ctx context.Context, vaultID uuid.UUID, id string) (domain.Note, error)
	GetByPath(ctx context.Context, vaultID uuid.UUID, path string) (domain.Note, error)
	ListForVault(ctx context.Context, vaultID uuid.UUID, limit, offset int) ([]domain.Note, error)
	Delete(ctx context.Context, vaultID uuid.UUID, id string) (int64, error)
	TouchContent(ctx context.Context, vaultID uuid.UUID, id string, at time.Time) (int64, error)
	Changes(ctx context.Context, vaultID uuid.UUID, after int64, limit int) (domain.NoteChanges, error)
}

// HeadPublisher hears every new vault seq so the account feed can emit
// vault.head (implemented by *feed.Broker). Must not block.
type HeadPublisher interface {
	VaultHead(vaultID uuid.UUID, seq int64)
}

// VaultLookup resolves a vault UUID to the row so the service can derive
// the on-disk slug for fs.Manager calls.
type VaultLookup interface {
	GetByID(ctx context.Context, id uuid.UUID) (domain.Vault, error)
}

// ---- Service ---------------------------------------------------------------

// FSEventSilencer is the seam that lets the FS watcher know "we're
// about to write this path ourselves, please drop the inotify echo".
// Pass a no-op (or nil) when the watcher is disabled.
type FSEventSilencer interface {
	SkipNext(absPath string)
}

// nopSilencer is the default when no watcher is wired. Keeps the
// Service callers branchless.
type nopSilencer struct{}

func (nopSilencer) SkipNext(string) {}

// Service orchestrates Postgres metadata, on-disk markdown bodies, the
// CRDT shadow, and audit recording. Methods are non-transactional in
// Phase 2.1/2.2; FS errors after a pg row write are best-effort rolled
// back. SPEC tightens transactional guarantees in Phase 3.
//
// The CRDT registry is optional: when nil, the snapshot/diff endpoints
// return 503 but the rest of the surface keeps working. This lets the
// server boot in environments without libyrs (smoke tests, fallback).
type Service struct {
	notes     NoteRepo
	vaults    VaultLookup
	fs        *fs.Manager
	audit     audit.Recorder
	resolver  capguard.Resolver
	crdt      *crdt.Registry
	docs      LiveDocs
	silencer  FSEventSilencer
	fedNotify FederationNotifier
	heads     HeadPublisher
	now       func() time.Time

	mirrorCheck func(ctx context.Context, vaultID uuid.UUID) bool
}

// SetMirrorCheck wires "is this vault a read-only mirror here" (lazy init
// off, /content 409 mirror_syncing). nil = never a mirror.
func (s *Service) SetMirrorCheck(fn func(ctx context.Context, vaultID uuid.UUID) bool) {
	s.mirrorCheck = fn
}

func (s *Service) isMirror(ctx context.Context, vaultID uuid.UUID) bool {
	return s.mirrorCheck != nil && s.mirrorCheck(ctx, vaultID)
}

// SetHeadPublisher wires the account feed; nil disables.
func (s *Service) SetHeadPublisher(p HeadPublisher) { s.heads = p }

// publishHead forwards a freshly committed seq to the feed.
func (s *Service) publishHead(vaultID uuid.UUID, seq int64) {
	if s.heads != nil && seq > 0 {
		s.heads.VaultHead(vaultID, seq)
	}
}

// upsertMeta writes metadata (bumping the vault seq) and publishes the head.
func (s *Service) upsertMeta(ctx context.Context, n domain.Note) error {
	seq, err := s.notes.Upsert(ctx, n)
	if err != nil {
		return err
	}
	s.publishHead(n.VaultID, seq)
	return nil
}

// deleteMeta deletes the row (tombstone + seq bump) and publishes the head.
func (s *Service) deleteMeta(ctx context.Context, vaultID uuid.UUID, id string) error {
	seq, err := s.notes.Delete(ctx, vaultID, id)
	if err != nil {
		return err
	}
	s.publishHead(vaultID, seq)
	return nil
}

// BumpContent records a live content edit: bumps the vault seq, stamps
// change_seq and updated_at, publishes vault.head. Called by the Hub's
// per-note coalescer at most once per second per note. A note deleted in
// the meantime is ignored.
func (s *Service) BumpContent(ctx context.Context, vaultID uuid.UUID, noteID string) {
	seq, err := s.notes.TouchContent(ctx, vaultID, noteID, s.now().UTC())
	if err != nil {
		return
	}
	s.publishHead(vaultID, seq)
}

// Changes returns one page of the vault's change log (GET /changes).
func (s *Service) Changes(ctx context.Context, vaultID uuid.UUID, after int64, limit int) (domain.NoteChanges, error) {
	return s.notes.Changes(ctx, vaultID, after, limit)
}

func NewService(
	notes NoteRepo,
	vaults VaultLookup,
	fsMgr *fs.Manager,
	a audit.Recorder,
	resolver capguard.Resolver,
	crdtReg *crdt.Registry,
	silencer FSEventSilencer,
) *Service {
	if notes == nil || vaults == nil || fsMgr == nil || resolver == nil {
		panic("notes.NewService: missing dependency")
	}
	if a == nil {
		a = audit.Noop{}
	}
	if silencer == nil {
		silencer = nopSilencer{}
	}
	return &Service{
		notes:    notes,
		vaults:   vaults,
		fs:       fsMgr,
		audit:    a,
		resolver: resolver,
		crdt:     crdtReg,
		silencer: silencer,
		now:      time.Now,
	}
}

// FederationNotifier hears about note lifecycle changes the registry
// persist hook can't see (creation seeds via InitFromText; deletion drops
// rows; moves/renames touch only metadata) so the F2 relay can propagate
// them to federated peers. Implementations must be fast and non-blocking.
type FederationNotifier interface {
	NoteCreated(vaultID uuid.UUID, noteID, path, title string)
	NoteDeleted(vaultID uuid.UUID, noteID string)
	NoteMoved(vaultID uuid.UUID, noteID, newPath, newTitle string)
}

// SetFederationNotifier wires the relay; nil disables.
func (s *Service) SetFederationNotifier(n FederationNotifier) { s.fedNotify = n }

// LiveDocs is the single authority over each note's in-memory CRDT doc
// (implemented by *wsync.Hub). Every CRDT mutation made by this service
// goes through it so live WebSocket clients receive the change and the
// room's debounced mirror never writes stale text (protocol §10 S2).
type LiveDocs interface {
	ApplyUpdate(ctx context.Context, vaultID uuid.UUID, noteID string, update []byte, opts wsync.ApplyOptions) (wsync.ApplyResult, error)
	ApplyText(ctx context.Context, vaultID uuid.UUID, noteID, newText string, expectSV []byte, opts wsync.ApplyOptions) (wsync.ApplyResult, error)
	View(ctx context.Context, vaultID uuid.UUID, noteID string, fn func(*crdt.Doc) error) error
	// DropNote discards any in-memory doc of the note's current CRDT
	// history and closes its live sockets with code (protocol §12).
	DropNote(vaultID uuid.UUID, noteID string, code int, reason string)
}

// dropLiveDoc ends the note's in-memory CRDT history (if a room holds
// one) and closes its sockets with 4404.
func (s *Service) dropLiveDoc(vaultID uuid.UUID, noteID string) {
	if s.docs != nil {
		s.docs.DropNote(vaultID, noteID, wsync.CloseNotFound, "note_deleted")
	}
}

// EpochRotated is the crdt.Registry epoch hook: a seed (lazy init)
// started a new CRDT history and stamped the new epoch at seq, so the
// account feed learns the vault head moved and /changes serves the note.
func (s *Service) EpochRotated(vaultID uuid.UUID, _ string, _ string, seq int64) {
	s.publishHead(vaultID, seq)
}

// SetLiveDocs wires the doc authority. Without it the CRDT write
// endpoints answer crdt_unavailable and PATCH body skips the CRDT.
func (s *Service) SetLiveDocs(d LiveDocs) { s.docs = d }

// CRDTInitBody returns a note's on-disk body for lazy CRDT seeding
// (crdt.InitSource). Unknown notes and notes without a file yet (e.g. a
// federation replica awaiting its first mirrored update) yield "".
func (s *Service) CRDTInitBody(ctx context.Context, vaultID uuid.UUID, noteID string) (string, error) {
	// A mirror never seeds (CRDT §10 S5): its notes get home's state over
	// the relay, and a file edited behind its back must not become a
	// second history.
	if s.isMirror(ctx, vaultID) {
		return "", nil
	}
	n, err := s.notes.Get(ctx, vaultID, noteID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return "", nil
		}
		return "", err
	}
	v, err := s.vaults.GetByID(ctx, vaultID)
	if err != nil {
		return "", err
	}
	_, body, err := s.fs.ReadNote(v.Slug, n.Path)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return "", nil
		}
		return "", err
	}
	return string(body), nil
}

// suppressFSEvent computes the absolute on-disk path for (slug, rel)
// and registers it in the watcher's skip map. Cheap; safe to call
// before every fs.Manager write.
func (s *Service) suppressFSEvent(slug, rel string) {
	if abs, err := s.fs.NotePath(slug, rel); err == nil {
		s.silencer.SkipNext(abs)
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
	// Kind is domain.NoteKindMarkdown (default when empty) or
	// domain.NoteKindCanvas.
	Kind  string
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
	// Publish sets (true) or removes (false) the frontmatter flag
	// "publish: true" that puts a note in a publish mirror's "flagged"
	// scope (docs/SPEC-ESPELHO-SELADO.md §A15.1).
	Publish *bool
	Actor   uuid.UUID
	IP      string
	UA      string
}

// ---- Service: Create -------------------------------------------------------

// Create slugifies Title into a unique note ID inside the vault, writes the
// file (markdown with frontmatter, or a raw canvas), mirrors metadata to
// Postgres, and audits.
//
// ID rule (docs/CRDT-CLIENT-PROTOCOL.md §13): a markdown note's id is the
// slug ([a-z0-9-]) and its path "<id>.md"; a canvas's id is
// "<slug>.canvas" and its path the same. Slugs never contain a dot, so
// the two id spaces are disjoint: "a.md" and "a.canvas" are the distinct
// ids "a" and "a.canvas". Ids never change afterwards (moves keep them).
//
// Conflict policy: if the derived ID (or its path) is already taken, an
// integer suffix is appended to the slug (`hello`, `hello-2`, `hello-3`,
// …) until a free slot is found. Limit: 50 attempts before ErrConflict.
func (s *Service) Create(ctx context.Context, vaultID uuid.UUID, in CreateInput) (domain.Note, error) {
	title := strings.TrimSpace(in.Title)
	if title == "" {
		return domain.Note{}, fmt.Errorf("%w: title is required", domain.ErrValidation)
	}
	kind := in.Kind
	if kind == "" {
		kind = domain.NoteKindMarkdown
	}
	switch kind {
	case domain.NoteKindMarkdown:
	case domain.NoteKindCanvas:
		if len(in.Tags) > 0 {
			return domain.Note{}, fmt.Errorf("%w: a canvas has no frontmatter, so no tags", domain.ErrValidation)
		}
		if strings.TrimSpace(in.Body) == "" || isEmptyCanvasJSON(in.Body) {
			in.Body = EmptyCanvas
		}
		// Only the create is checked: live edits may be mid-way through
		// a JSON change, so later writes are not (SPEC-PARTE2 §6).
		if !json.Valid([]byte(in.Body)) {
			return domain.Note{}, fmt.Errorf("%w: canvas body must be valid JSON", domain.ErrValidation)
		}
	default:
		return domain.Note{}, fmt.Errorf("%w: kind must be markdown or canvas", domain.ErrValidation)
	}
	if err := validateBody(in.Body); err != nil {
		return domain.Note{}, err
	}
	v, err := s.vaults.GetByID(ctx, vaultID)
	if err != nil {
		return domain.Note{}, err
	}

	base := slugifyTitle(title)
	id, relPath, err := s.allocateNoteID(ctx, vaultID, base, kind)
	if err != nil {
		return domain.Note{}, err
	}
	if kind == domain.NoteKindCanvas {
		// No frontmatter: the title is the file name, so a client that
		// only sees the file derives the same one.
		title = domain.NoteStem(relPath)
	}
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
	s.suppressFSEvent(v.Slug, relPath)
	if err := s.fs.WriteNote(v.Slug, relPath, front, []byte(in.Body)); err != nil {
		return domain.Note{}, fmt.Errorf("write note: %w", err)
	}

	// A new note id starts a new CRDT history: fresh epoch, written with
	// the row and reused by the seed below (no second rotation).
	note := domain.Note{
		ID:        id,
		VaultID:   vaultID,
		Path:      relPath,
		Title:     title,
		CreatedAt: now,
		UpdatedAt: now,
		CRDTEpoch: domain.NewCRDTEpoch(),
	}
	seq, err := s.notes.Upsert(ctx, note)
	if err != nil {
		// Roll back the on-disk file so we don't leave orphans.
		_ = s.fs.DeleteNote(v.Slug, relPath)
		return domain.Note{}, err
	}

	// Seed the CRDT so live sync, /snapshot and /diff have a base state.
	// This server is the note's home, so it is the single seeder (§10 S5).
	// A failure rolls the create back: leaving a note whose CRDT is
	// unseeded would let the first live edit race lazy init.
	if s.crdt != nil {
		// A room left over from a deleted note with this id must not
		// serve (or persist onto) the new history.
		s.dropLiveDoc(vaultID, id)
		if _, err := s.crdt.InitFromTextEpoch(ctx, vaultID, id, in.Body, note.CRDTEpoch, in.Actor, "snapshot-init"); err != nil {
			// The row's seq may already be visible to a reader, so the
			// rollback is a real (tombstoned) delete.
			_ = s.deleteMeta(ctx, vaultID, id)
			s.suppressFSEvent(v.Slug, relPath)
			_ = s.fs.DeleteNote(v.Slug, relPath)
			return domain.Note{}, fmt.Errorf("seed crdt: %w", err)
		}
	}
	// Re-read: if a concurrent first load seeded the note from the file
	// before us, the row carries that seed's epoch (and seq).
	if fresh, err := s.notes.Get(ctx, vaultID, id); err == nil {
		note = fresh
		seq = max(seq, fresh.ChangeSeq)
	}
	s.publishHead(vaultID, seq)
	// InitFromText bypasses PersistChange, so federated peers need an
	// explicit nudge for brand-new notes (v3 F2).
	if s.fedNotify != nil {
		s.fedNotify.NoteCreated(vaultID, id, relPath, title)
	}

	s.recordAudit(ctx, in.Actor, vaultID, domain.ActionNoteCreate, in.IP, in.UA, map[string]any{
		"note_id": id,
		"path":    relPath,
		"title":   title,
	})
	return note, nil
}

// EmptyCanvas is the body of a canvas created empty: Obsidian's
// multi-line layout, so the first card two clients add concurrently is a
// small line-hunk insert that merges into valid JSON (on the single-line
// form both inserts land inside the same "[]" and the merge breaks the
// JSON). Existing canvases are never rewritten.
const EmptyCanvas = "{\n\t\"nodes\":[],\n\t\"edges\":[]\n}"

// isEmptyCanvasJSON reports whether body is exactly an empty canvas
// ({"nodes":[],"edges":[]} in any whitespace layout).
func isEmptyCanvasJSON(body string) bool {
	var buf bytes.Buffer
	if err := json.Compact(&buf, []byte(body)); err != nil {
		return false
	}
	return buf.String() == `{"nodes":[],"edges":[]}`
}

// validateBody applies the limits shared by every note kind: valid UTF-8
// and at most domain.MaxNoteBodyBytes.
func validateBody(body string) error {
	if len(body) > domain.MaxNoteBodyBytes {
		return fmt.Errorf("%w: body larger than %d bytes", domain.ErrValidation, domain.MaxNoteBodyBytes)
	}
	if !utf8.ValidString(body) {
		return fmt.Errorf("%w: body is not valid UTF-8", domain.ErrValidation)
	}
	return nil
}

// allocateNoteID picks the first free id of the kind's id rule (see
// Create) whose path is also free: a note moved onto "hello.md" keeps
// its own id, so a free id "hello" does not imply a free path.
func (s *Service) allocateNoteID(ctx context.Context, vaultID uuid.UUID, base, kind string) (id, relPath string, err error) {
	const maxAttempts = 50
	for i := 0; i < maxAttempts; i++ {
		stem := base
		if i > 0 {
			stem = fmt.Sprintf("%s-%d", base, i+1)
		}
		id, relPath = stem, stem+domain.NoteExtMarkdown
		if kind == domain.NoteKindCanvas {
			id = stem + domain.NoteExtCanvas
			relPath = id
		}
		if _, err := s.notes.Get(ctx, vaultID, id); err == nil {
			continue
		} else if !errors.Is(err, domain.ErrNotFound) {
			return "", "", err
		}
		if _, err := s.notes.GetByPath(ctx, vaultID, relPath); err == nil {
			continue
		} else if !errors.Is(err, domain.ErrNotFound) {
			return "", "", err
		}
		return id, relPath, nil
	}
	return "", "", fmt.Errorf("%w: too many ID collisions for %q", domain.ErrConflict, base)
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
		// The row exists; callers can tell "no file yet" from "no note".
		return n, nil, nil, err
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

	canvas := domain.IsCanvasPath(n.Path)
	if canvas && (in.Title != nil || in.Tags != nil || in.Publish != nil) {
		return domain.Note{}, fmt.Errorf("%w: a canvas has no frontmatter: its title is its file name (move it to rename)", domain.ErrValidation)
	}
	if in.Body != nil {
		if err := validateBody(*in.Body); err != nil {
			return domain.Note{}, err
		}
	}

	moved := false
	newPath := n.Path
	if in.Path != nil {
		cleaned, err := validateNoteRelPath(*in.Path)
		if err != nil {
			return domain.Note{}, err
		}
		if err := sameKind(n.Path, cleaned); err != nil {
			return domain.Note{}, err
		}
		if cleaned != n.Path {
			if _, err := s.notes.GetByPath(ctx, vaultID, cleaned); err == nil {
				return domain.Note{}, fmt.Errorf("%w: path %q already exists", domain.ErrConflict, cleaned)
			} else if !errors.Is(err, domain.ErrNotFound) {
				return domain.Note{}, err
			}
			// A move fires events on BOTH the source (Rename) and the
			// destination (Create); silence both.
			s.suppressFSEvent(v.Slug, n.Path)
			s.suppressFSEvent(v.Slug, cleaned)
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
	if canvas {
		newTitle = domain.NoteStem(newPath)
	}
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
	if in.Publish != nil {
		cur, _ := front["publish"].(bool)
		if *in.Publish != cur {
			if *in.Publish {
				front["publish"] = true
			} else {
				delete(front, "publish")
			}
			edited = true
		}
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
		s.suppressFSEvent(v.Slug, newPath)
		if err := s.fs.WriteNote(v.Slug, newPath, front, body); err != nil {
			return domain.Note{}, err
		}
		// Route the body into the note's authoritative CRDT doc (the
		// live room's when one is open) so connected editors receive it
		// and the room mirror cannot later overwrite the file with stale
		// text. PATCH body is whole-text replacement: anything a live
		// editor typed that the caller did not see is replaced (LWW).
		// Best-effort: a CRDT failure doesn't roll back the FS write.
		if in.Body != nil && s.docs != nil {
			_, _ = s.docs.ApplyText(ctx, vaultID, id, *in.Body, nil, wsync.ApplyOptions{
				Actor: in.Actor, Origin: "web-patch", Mirror: wsync.MirrorNow,
			})
		}
	}

	updated := domain.Note{
		ID:        id,
		VaultID:   vaultID,
		Path:      newPath,
		Title:     newTitle,
		CreatedAt: n.CreatedAt,
		UpdatedAt: now,
		CRDTEpoch: n.CRDTEpoch,
	}
	if !edited && !moved {
		return n, nil
	}
	if err := s.upsertMeta(ctx, updated); err != nil {
		return domain.Note{}, err
	}
	// Path/title changes are metadata-only: the CRDT persist hook never
	// sees them, so federated peers need an explicit nudge.
	if (moved || newTitle != n.Title) && s.fedNotify != nil {
		s.fedNotify.NoteMoved(vaultID, id, newPath, newTitle)
	}
	// Tags and the publish flag live only in the frontmatter: replicate
	// them (G1); a publish link re-evaluates its scope on it.
	if in.Tags != nil || in.Publish != nil {
		s.notifyMetaChanged(vaultID, id)
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

// sameKind refuses a move that would change a note's kind: a markdown
// file renamed to .canvas (or back) would be read with the other format.
func sameKind(oldPath, newPath string) error {
	if domain.NoteKindOf(oldPath) != domain.NoteKindOf(newPath) {
		return fmt.Errorf("%w: a move cannot change the note kind (keep the %s extension)", domain.ErrValidation, domain.NoteExt(domain.NoteKindOf(oldPath)))
	}
	return nil
}

// validateNoteRelPath normalises (trim + path.Clean) and then applies
// domain.ValidateNotePath: rejects absolute paths, parent traversals,
// hidden/dot segments, and any path that does not end in `.md` or
// `.canvas`. fs.SafeJoin enforces the same plus symlink-escape — this
// check exists to fail early with a friendlier error.
func validateNoteRelPath(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("%w: path is required", domain.ErrValidation)
	}
	cleaned := path.Clean(s)
	if cleaned == "." || strings.HasPrefix(cleaned, "/") || strings.HasPrefix(cleaned, "..") {
		return "", fmt.Errorf("%w: path %q escapes vault", domain.ErrValidation, raw)
	}
	// Canonical-form policy shared with the federation relay: no hidden or
	// dot segments (keeps writes out of .lumi/), no backslashes, bounded.
	if err := domain.ValidateNotePath(cleaned); err != nil {
		return "", err
	}
	return cleaned, nil
}

// ---- Service: Delete -------------------------------------------------------

func (s *Service) Delete(ctx context.Context, vaultID uuid.UUID, id string, actor uuid.UUID, ip, ua string) error {
	return s.deleteInternal(ctx, vaultID, id, actor, ip, ua, true)
}

// DeleteFromFederation applies a deletion relayed from a federated peer.
// Skips the federation notifier — the relay layer fans the deletion to the
// *other* links itself, so notifying here would bounce it back to its
// source.
func (s *Service) DeleteFromFederation(ctx context.Context, vaultID uuid.UUID, id string) error {
	return s.deleteInternal(ctx, vaultID, id, uuid.Nil, "", "", false)
}

func (s *Service) deleteInternal(ctx context.Context, vaultID uuid.UUID, id string, actor uuid.UUID, ip, ua string, notify bool) error {
	n, err := s.notes.Get(ctx, vaultID, id)
	if err != nil {
		return err
	}
	v, err := s.vaults.GetByID(ctx, vaultID)
	if err != nil {
		return err
	}
	if err := s.deleteMeta(ctx, vaultID, id); err != nil {
		return err
	}
	// The CRDT history ends with the row (snapshot + log cascade): drop
	// the live room so sockets get 4404 and a recreate under the same id
	// starts from the new seed, never from this doc.
	s.dropLiveDoc(vaultID, id)
	if notify && s.fedNotify != nil {
		s.fedNotify.NoteDeleted(vaultID, id)
	}
	s.suppressFSEvent(v.Slug, n.Path)
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

// ---- CRDT snapshot + diff --------------------------------------------------

// errCRDTUnavailable is returned by GetSnapshot/ApplyDiff when the
// service was constructed without a CRDT registry (libyrs not linked or
// intentionally disabled).
var errCRDTUnavailable = fmt.Errorf("%w: crdt not available", domain.ErrValidation)

// errBaseRequired: a text /diff without a usable base (protocol §10 S1).
var errBaseRequired = fmt.Errorf("%w: base_required", domain.ErrConflict)

// SnapshotResult is the wire shape of GET /snapshot and POST /diff —
// text + opaque state vector (lib0 v1) + full encoded state. The handler
// base64-encodes the binary fields.
type SnapshotResult struct {
	NoteID string
	Path   string
	// CRDTEpoch is the lineage the state below belongs to (protocol §12).
	CRDTEpoch   string
	Text        string
	VectorClock []byte
	// State is the full lib0-v1 encoded document (EncodeStateAsUpdate).
	// Opaque-editor clients keep it as the base for a 3-way /diff.
	State []byte
}

// GetSnapshot returns the note's current CRDT text, state vector and full
// state, read from the authoritative doc (the live room's when open).
func (s *Service) GetSnapshot(ctx context.Context, vaultID uuid.UUID, id string) (SnapshotResult, error) {
	if s.crdt == nil || s.docs == nil {
		return SnapshotResult{}, errCRDTUnavailable
	}
	var out SnapshotResult
	n, err := s.viewWithEpoch(ctx, vaultID, id, func(doc *crdt.Doc) error {
		var err error
		if out.Text, err = doc.Text(); err != nil {
			return err
		}
		if out.VectorClock, err = doc.StateVectorV1(); err != nil {
			return err
		}
		out.State, err = doc.EncodeStateAsUpdate()
		return err
	})
	if err != nil {
		return SnapshotResult{}, err
	}
	out.NoteID, out.Path, out.CRDTEpoch = n.ID, n.Path, n.CRDTEpoch
	return out, nil
}

// StateVectorResult is the wire shape of GET /state-vector.
type StateVectorResult struct {
	NoteID      string
	CRDTEpoch   string
	StateVector []byte
}

// GetStateVector returns the note's CRDT epoch and current state vector:
// the cheap way for an offline-replica client to confirm the server has
// absorbed its updates (sv covers the replica's) without downloading the
// full state from /snapshot.
func (s *Service) GetStateVector(ctx context.Context, vaultID uuid.UUID, id string) (StateVectorResult, error) {
	if s.crdt == nil || s.docs == nil {
		return StateVectorResult{}, errCRDTUnavailable
	}
	var sv []byte
	n, err := s.viewWithEpoch(ctx, vaultID, id, func(doc *crdt.Doc) error {
		var err error
		sv, err = doc.StateVectorV1()
		return err
	})
	if err != nil {
		return StateVectorResult{}, err
	}
	return StateVectorResult{NoteID: n.ID, CRDTEpoch: n.CRDTEpoch, StateVector: sv}, nil
}

// errEpochUnstable: the note's lineage kept changing while being read.
var errEpochUnstable = fmt.Errorf("%w: crdt_epoch changed while reading; retry", domain.ErrConflict)

// viewWithEpoch runs fn on the note's authoritative doc and returns the
// note row whose crdt_epoch is guaranteed to describe the doc fn saw:
// the epoch is read before and after the view and must match (epochs
// are random, so equal values mean no new history started in between —
// e.g. the view itself lazily seeding the note, or a delete+recreate).
// A changed epoch re-runs the read.
func (s *Service) viewWithEpoch(ctx context.Context, vaultID uuid.UUID, id string, fn func(*crdt.Doc) error) (domain.Note, error) {
	for attempt := 0; attempt < 3; attempt++ {
		before, err := s.notes.Get(ctx, vaultID, id)
		if err != nil {
			return domain.Note{}, err
		}
		if err := s.docs.View(ctx, vaultID, id, fn); err != nil {
			return domain.Note{}, err
		}
		after, err := s.notes.Get(ctx, vaultID, id)
		if err != nil {
			return domain.Note{}, err
		}
		if after.CRDTEpoch == before.CRDTEpoch {
			return after, nil
		}
	}
	return domain.Note{}, errEpochUnstable
}

// DiffInput is the text-merge form of POST /diff.
type DiffInput struct {
	// Text is the full edited body.
	Text string
	// BaseState is the full encoded state (GET /snapshot `state`) the
	// edit was made on. Preferred: enables a real 3-way merge.
	BaseState []byte
	// BaseClock is the state vector (GET /snapshot `vector_clock`) the
	// edit was made on. Accepted only while it still equals the current
	// state vector (nothing concurrent happened).
	BaseClock []byte
}

// ApplyDiff is the opaque-editor "I rewrote the whole body" path.
//
//   - With BaseState: rebuild the base, diff base text → Text, and merge
//     those ops into the current doc (3-way; concurrent edits survive).
//   - With only BaseClock: plain diff against current text, but only if
//     the clock still equals the current state vector — atomically
//     checked; otherwise errBaseRequired.
//   - With neither: errBaseRequired (HTTP 409). The old behaviour —
//     diffing against current state — silently discarded every edit the
//     caller had not seen (vector V9a).
//
// Caveat: deletions do not advance a state vector, so the BaseClock path
// cannot see a concurrent pure deletion (it would be re-inserted).
// Clients should send BaseState.
func (s *Service) ApplyDiff(
	ctx context.Context,
	vaultID uuid.UUID, id string,
	in DiffInput,
	originKind string,
	actor uuid.UUID, ip, ua string,
) (SnapshotResult, error) {
	if s.crdt == nil || s.docs == nil {
		return SnapshotResult{}, errCRDTUnavailable
	}
	n, err := s.notes.Get(ctx, vaultID, id)
	if err != nil {
		return SnapshotResult{}, err
	}
	// WantState: the response carries the post-merge state so the
	// client has its next base without a /snapshot round-trip.
	opts := wsync.ApplyOptions{Actor: actor, Origin: originKind, Mirror: wsync.MirrorNow, WantState: true}

	var res wsync.ApplyResult
	switch {
	case len(in.BaseState) > 0:
		tw, err := crdt.ThreeWayUpdate(in.BaseState, in.Text)
		if err != nil {
			return SnapshotResult{}, err
		}
		// The base must be a version this doc descends from, otherwise
		// the derived ops reference items the server never saw and
		// would sit as a pending update forever.
		var covered bool
		if err := s.docs.View(ctx, vaultID, id, func(doc *crdt.Doc) error {
			raw, err := doc.StateVectorV1()
			if err != nil {
				return err
			}
			cur, err := crdt.DecodeStateVector(raw)
			if err != nil {
				return err
			}
			covered = cur.Covers(tw.BaseSV)
			return nil
		}); err != nil {
			return SnapshotResult{}, err
		}
		if !covered {
			return SnapshotResult{}, fmt.Errorf("%w: base_state contains changes this server does not have", crdt.ErrBaseMismatch)
		}
		res, err = s.docs.ApplyUpdate(ctx, vaultID, id, tw.Update, opts)
		if err != nil {
			return SnapshotResult{}, err
		}
	case len(in.BaseClock) > 0:
		res, err = s.docs.ApplyText(ctx, vaultID, id, in.Text, in.BaseClock, opts)
		if errors.Is(err, crdt.ErrBaseMismatch) {
			return SnapshotResult{}, fmt.Errorf("%w: base_clock is stale; resend with base_state", errBaseRequired)
		}
		if err != nil {
			return SnapshotResult{}, err
		}
	default:
		return SnapshotResult{}, errBaseRequired
	}
	return s.finishCRDTWrite(ctx, vaultID, n, res, originKind, actor, ip, ua)
}

// ApplyUpdate is the CRDT-peer "here's a Yjs update I computed
// locally" path. The update (lib0 v1) is merged into the note's
// authoritative doc — the live room's when one is open — persisted once,
// broadcast to live clients and mirrored to disk. Empty or already-known
// updates are no-ops.
func (s *Service) ApplyUpdate(
	ctx context.Context,
	vaultID uuid.UUID, id string,
	update []byte,
	originKind string,
	actor uuid.UUID, ip, ua string,
) (SnapshotResult, error) {
	if s.crdt == nil || s.docs == nil {
		return SnapshotResult{}, errCRDTUnavailable
	}
	n, err := s.notes.Get(ctx, vaultID, id)
	if err != nil {
		return SnapshotResult{}, err
	}
	res, err := s.docs.ApplyUpdate(ctx, vaultID, id, update, wsync.ApplyOptions{
		Actor: actor, Origin: originKind, Mirror: wsync.MirrorNow, WantState: true,
	})
	if err != nil {
		return SnapshotResult{}, fmt.Errorf("%w: apply update: %v", domain.ErrValidation, err)
	}
	return s.finishCRDTWrite(ctx, vaultID, n, res, originKind, actor, ip, ua)
}

// finishCRDTWrite audits a REST CRDT write and shapes the response. The
// disk write and updated_at bump already happened in the Hub's
// synchronous mirror (WriteBodyFromCRDT).
func (s *Service) finishCRDTWrite(ctx context.Context, vaultID uuid.UUID, n domain.Note, res wsync.ApplyResult, originKind string, actor uuid.UUID, ip, ua string) (SnapshotResult, error) {
	if res.MirrorErr != nil {
		// The CRDT change is persisted and broadcast; the file is behind.
		// Surface it so the client knows; a retry is an idempotent no-op
		// for the CRDT and re-runs the mirror on the next change.
		return SnapshotResult{}, fmt.Errorf("crdt fs mirror: %w", res.MirrorErr)
	}
	if res.Changed {
		s.recordAudit(ctx, actor, vaultID, domain.ActionNoteEdit, ip, ua, map[string]any{
			"note_id": n.ID,
			"path":    n.Path,
			"source":  originKind,
			"bytes":   len(res.Update),
		})
	}
	// The write went into the history the row's epoch names now; re-read
	// it in case the write's own room load lazily seeded the note.
	epoch := n.CRDTEpoch
	if cur, err := s.notes.Get(ctx, vaultID, n.ID); err == nil {
		epoch = cur.CRDTEpoch
	}
	return SnapshotResult{
		NoteID:      n.ID,
		Path:        n.Path,
		CRDTEpoch:   epoch,
		Text:        res.Text,
		VectorClock: res.StateVector,
		State:       res.State,
	}, nil
}

// WriteBodyFromCRDT mirrors a CRDT-derived body back to the on-disk
// markdown file. Called by the WebSocket hub's mirror (debounced for
// live edits, synchronous for REST writes) so CRDT changes propagate to
// FS-reading clients (TUI, apple).
//
// Frontmatter is preserved; only the body region is replaced. The FS
// watcher path is suppressed so we don't bounce our own write back
// into the CRDT as a synthetic external edit.
//
// Errors are returned so the hub can log them; failures here mean
// the CRDT and FS are temporarily diverged but the CRDT remains
// authoritative for the active session.
func (s *Service) WriteBodyFromCRDT(ctx context.Context, vaultID uuid.UUID, noteID, text string) error {
	n, err := s.notes.Get(ctx, vaultID, noteID)
	if err != nil {
		return err
	}
	v, err := s.vaults.GetByID(ctx, vaultID)
	if err != nil {
		return err
	}
	front, _, err := s.fs.ReadNote(v.Slug, n.Path)
	if err != nil {
		if !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		// First mirror of a federation-announced note: create the file.
		front = map[string]any{"id": noteID, "title": n.Title, "created_at": n.CreatedAt.UTC().Format(time.RFC3339)}
	}
	now := s.now().UTC()
	front["updated_at"] = now.Format(time.RFC3339)
	if _, ok := front["id"]; !ok {
		front["id"] = noteID
	}
	s.suppressFSEvent(v.Slug, n.Path)
	// No pg write here: the Hub's content coalescer (BumpContent) owns
	// notes.updated_at / change_seq for content edits, at most once per
	// second per note. (The old unconditional upsert could also resurrect
	// a row deleted between the Get above and the write.)
	return s.fs.WriteNote(v.Slug, n.Path, front, []byte(text))
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
	// CRDT TUI-style snapshot + diff sync — see SPEC.md "CRDT integration".
	r.Get("/vaults/:vault/notes/:id/snapshot",
		capguard.RequireCapability(resolver, domain.CapNoteRead),
		h.getSnapshot,
	)
	// Cheap ack probe for offline-replica clients: epoch + state vector.
	r.Get("/vaults/:vault/notes/:id/state-vector",
		capguard.RequireCapability(resolver, domain.CapNoteRead),
		h.getStateVector,
	)
	r.Post("/vaults/:vault/notes/:id/diff",
		capguard.RequireCapability(resolver, domain.CapNoteEdit),
		h.applyDiff,
	)
	// Incremental change log for the account feed (SPEC-LIVROS §3.5).
	r.Get("/vaults/:vault/changes",
		capguard.RequireCapability(resolver, domain.CapNoteRead),
		h.changes,
	)
}

// Change-log page size (SPEC-LIVROS §3.5).
const (
	defaultChangesLimit = 500
	maxChangesLimit     = 1000
)

type changeNoteDTO struct {
	noteDTO
	ChangeSeq int64 `json:"change_seq"`
}

type tombstoneDTO struct {
	ID  string `json:"id"`
	Seq int64  `json:"seq"`
}

// changes — GET /api/vaults/:vault/changes?after=N&limit=500
//
// 200 {"notes":[NoteSummary + change_seq],"deleted":[{"id","seq"}],
//
//	"head":H,"more":bool}
//
// Entries have seq in (after, head], ascending; at most limit of them in
// total across both arrays. more=true → call again with after = the
// highest seq received; more=false → the cursor is now head. after=0 (or
// omitted) means everything. A cursor below the vault's tombstone floor
// answers 410 {"error":"resync_required","head":H}: list everything with
// GET /notes and set the cursor to that head.
func (h *Handlers) changes(c *fiber.Ctx) error {
	vaultID, err := capguard.WithVaultID(c)
	if err != nil {
		return nil
	}
	var after int64
	if raw := c.Query("after"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 0 {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_after"})
		}
		after = n
	}
	limit := defaultChangesLimit
	if raw := c.Query("limit"); raw != "" {
		n, err := atoiPos(raw)
		if err != nil || n == 0 {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_limit"})
		}
		limit = min(n, maxChangesLimit)
	}
	page, err := h.svc.Changes(c.UserContext(), vaultID, after, limit)
	if err != nil {
		var resync *domain.ResyncRequiredError
		if errors.As(err, &resync) {
			return c.Status(http.StatusGone).JSON(fiber.Map{"error": "resync_required", "head": resync.Head})
		}
		return mapErr(c, err)
	}
	notesOut := make([]changeNoteDTO, 0, len(page.Notes))
	for _, n := range page.Notes {
		notesOut = append(notesOut, changeNoteDTO{noteDTO: toDTO(n), ChangeSeq: n.ChangeSeq})
	}
	deleted := make([]tombstoneDTO, 0, len(page.Deleted))
	for _, t := range page.Deleted {
		deleted = append(deleted, tombstoneDTO{ID: t.ID, Seq: t.Seq})
	}
	return c.JSON(fiber.Map{
		"notes":   notesOut,
		"deleted": deleted,
		"head":    page.Head,
		"more":    page.More,
	})
}

type noteDTO struct {
	ID        string `json:"id"`
	VaultID   string `json:"vault_id"`
	Path      string `json:"path"`
	Title     string `json:"title"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	// CRDTEpoch: opaque CRDT lineage id (protocol §12); compare for
	// equality only.
	CRDTEpoch string `json:"crdt_epoch,omitempty"`
	// Kind is "markdown" or "canvas", derived from the path extension.
	Kind string `json:"kind"`
}

func toDTO(n domain.Note) noteDTO {
	return noteDTO{
		ID:        n.ID,
		VaultID:   n.VaultID.String(),
		Path:      n.Path,
		Title:     n.Title,
		CreatedAt: n.CreatedAt.UTC().Format(time.RFC3339),
		UpdatedAt: n.UpdatedAt.UTC().Format(time.RFC3339),
		CRDTEpoch: n.CRDTEpoch,
		Kind:      domain.NoteKindOf(n.Path),
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
	Kind  string   `json:"kind,omitempty"` // "markdown" (default) or "canvas"
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
		Kind:  req.Kind,
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
		// A mirror lists notes before their content arrived over the
		// relay: say so instead of a bare 404 (§A6.4).
		if errors.Is(err, domain.ErrNotFound) && n.ID != "" && h.svc.isMirror(c.UserContext(), vaultID) {
			return c.Status(http.StatusConflict).JSON(fiber.Map{"error": "mirror_syncing"})
		}
		return mapErr(c, err)
	}
	return c.JSON(fiber.Map{
		"id":          n.ID,
		"vault_id":    n.VaultID.String(),
		"path":        n.Path,
		"kind":        domain.NoteKindOf(n.Path),
		"frontmatter": yamlToJSON(front),
		"body":        string(body),
	})
}

type updateReq struct {
	Title *string   `json:"title,omitempty"`
	Body  *string   `json:"body,omitempty"`
	Path  *string   `json:"path,omitempty"`
	Tags  *[]string `json:"tags,omitempty"`
	// Publish toggles the frontmatter flag publish: true (§A15.1).
	Publish *bool `json:"publish,omitempty"`
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
		Title:   req.Title,
		Body:    req.Body,
		Path:    req.Path,
		Tags:    req.Tags,
		Publish: req.Publish,
		Actor:   uid,
		IP:      c.IP(),
		UA:      string(c.Request().Header.UserAgent()),
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

// getSnapshot — GET /api/vaults/:vault/notes/:id/snapshot
//
// Returns { id, path, crdt_epoch, text, vector_clock, state }:
//   - crdt_epoch: the CRDT lineage the state belongs to (protocol §12).
//   - vector_clock: base64 lib0-v1 state vector (unchanged; REST-only CRDT
//     clients use it as lastServerSV for encodeStateAsUpdate).
//   - state: base64 full lib0-v1 update (EncodeStateAsUpdate). Opaque
//     editors keep it as the base for a 3-way POST /diff (`base_state`).
func (h *Handlers) getSnapshot(c *fiber.Ctx) error {
	vaultID, err := capguard.WithVaultID(c)
	if err != nil {
		return nil
	}
	id, err := noteIDParam(c)
	if err != nil {
		return nil
	}
	r, err := h.svc.GetSnapshot(c.UserContext(), vaultID, id)
	if err != nil {
		return mapCRDTErr(c, err)
	}
	return c.JSON(fiber.Map{
		"id":           r.NoteID,
		"path":         r.Path,
		"crdt_epoch":   r.CRDTEpoch,
		"text":         r.Text,
		"vector_clock": base64.StdEncoding.EncodeToString(r.VectorClock),
		"state":        base64.StdEncoding.EncodeToString(r.State),
	})
}

// getStateVector — GET /api/vaults/:vault/notes/:id/state-vector
//
// Returns { id, crdt_epoch, state_vector } where state_vector is the
// base64 lib0-v1 state vector (same encoding as /snapshot vector_clock).
// Same auth as /snapshot (note.read); a fraction of its cost: no text,
// no full state. Clients use it to confirm a replica's updates were
// absorbed (sv covers the replica's) and that the lineage still matches.
func (h *Handlers) getStateVector(c *fiber.Ctx) error {
	vaultID, err := capguard.WithVaultID(c)
	if err != nil {
		return nil
	}
	id, err := noteIDParam(c)
	if err != nil {
		return nil
	}
	r, err := h.svc.GetStateVector(c.UserContext(), vaultID, id)
	if err != nil {
		return mapCRDTErr(c, err)
	}
	c.Set(fiber.HeaderCacheControl, "no-store")
	return c.JSON(fiber.Map{
		"id":           r.NoteID,
		"crdt_epoch":   r.CRDTEpoch,
		"state_vector": base64.StdEncoding.EncodeToString(r.StateVector),
	})
}

type diffReq struct {
	// Text is the full edited body (text-merge form). Requires a base:
	// `base_state` (preferred) or a still-current `base_clock`.
	Text string `json:"text,omitempty"`
	// BaseState is the base64 full state from GET /snapshot `state` that
	// the edit was made on. Enables a 3-way merge.
	BaseState string `json:"base_state,omitempty"`
	// BaseClock is the base64 state vector from GET /snapshot
	// `vector_clock`. Without base_state the write is accepted only if it
	// still equals the current state vector.
	BaseClock string `json:"base_clock,omitempty"`
	// Update is a base64-encoded lib0-v1 Y.Doc update produced by a
	// CRDT-peer client (e.g. apple-client's LumiCRDT). Applied as a CRDT
	// merge. Mutually exclusive with `Text`.
	Update string `json:"update,omitempty"`
	// Origin labels the source; must be one of clientOriginAllowlist.
	// Defaults to "tui-diff" when omitted.
	Origin string `json:"origin,omitempty"`
}

// clientOriginAllowlist is the set of origin labels a REST client may
// claim. origin_kind steers server behaviour — "federation:<peer>" suppresses
// fan-out to that peer (relay echo guard) and "fs-watcher" changes broadcast
// semantics — so arbitrary client strings must never reach it.
var clientOriginAllowlist = map[string]struct{}{
	"tui-diff":   {},
	"apple-diff": {},
	"web":        {},
	"web-diff":   {},
	"tui":        {},
	"apple":      {},
}

// defaultClientOrigin is used when the client omits origin.
const defaultClientOrigin = "tui-diff"

// clientOrigin validates a client-supplied origin label against the
// allowlist; empty means defaultClientOrigin.
func clientOrigin(raw string) (string, error) {
	o := strings.TrimSpace(raw)
	if o == "" {
		return defaultClientOrigin, nil
	}
	if _, ok := clientOriginAllowlist[o]; !ok {
		return "", fmt.Errorf("%w: origin %q is not an allowed client origin", domain.ErrValidation, o)
	}
	return o, nil
}

func decodeB64Field(c *fiber.Ctx, name, raw string) ([]byte, bool) {
	if raw == "" {
		return nil, true
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		_ = c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error":  "invalid_body",
			"detail": name + " is not valid base64",
		})
		return nil, false
	}
	return b, true
}

// applyDiff — POST /api/vaults/:vault/notes/:id/diff
//
// Accepts two body shapes (mutually exclusive):
//   - `{update, origin?}` — a lib0-v1 Y.Doc update computed by a CRDT
//     client (e.g. on a doc restored from /snapshot `state`); merged.
//   - `{text, base_state | base_clock, origin?}` — opaque-editor form.
//     With base_state the server performs the 3-way merge itself. With
//     only base_clock the write is accepted iff the clock is current.
//     With neither: 409 {"error":"base_required"} (no more LWW).
//
// Errors: 409 base_required (no/stale base), 409 base_mismatch
// (base_state is not an ancestor of the server's state), 409 base_too_old
// (base_state cannot be reconstructed at all — refetch /snapshot).
// Success: { id, path, text, vector_clock, state } — state (base64 full
// lib0-v1 doc, as GET /snapshot) is the client's next base_state.
func (h *Handlers) applyDiff(c *fiber.Ctx) error {
	vaultID, err := capguard.WithVaultID(c)
	if err != nil {
		return nil
	}
	id, err := noteIDParam(c)
	if err != nil {
		return nil
	}
	var req diffReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_body"})
	}
	origin, err := clientOrigin(req.Origin)
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error":  "invalid_origin",
			"detail": err.Error(),
		})
	}
	uid, _ := capguard.UserIDFrom(c)
	ip, ua := c.IP(), string(c.Request().Header.UserAgent())

	var r SnapshotResult
	if req.Update != "" {
		// Reject ambiguous payloads that carry both shapes so a bug in
		// the client can't silently land "the wrong" path on the server.
		if req.Text != "" || req.BaseState != "" {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{
				"error":  "invalid_body",
				"detail": "set exactly one of `text` or `update`",
			})
		}
		updateBytes, ok := decodeB64Field(c, "update", req.Update)
		if !ok {
			return nil
		}
		r, err = h.svc.ApplyUpdate(c.UserContext(), vaultID, id, updateBytes, origin, uid, ip, ua)
	} else {
		baseState, ok := decodeB64Field(c, "base_state", req.BaseState)
		if !ok {
			return nil
		}
		baseClock, ok := decodeB64Field(c, "base_clock", req.BaseClock)
		if !ok {
			return nil
		}
		r, err = h.svc.ApplyDiff(c.UserContext(), vaultID, id, DiffInput{
			Text: req.Text, BaseState: baseState, BaseClock: baseClock,
		}, origin, uid, ip, ua)
	}
	if err != nil {
		return mapCRDTErr(c, err)
	}
	out := fiber.Map{
		"id":           r.NoteID,
		"path":         r.Path,
		"crdt_epoch":   r.CRDTEpoch,
		"text":         r.Text,
		"vector_clock": base64.StdEncoding.EncodeToString(r.VectorClock),
	}
	if len(r.State) > 0 {
		out["state"] = base64.StdEncoding.EncodeToString(r.State)
	}
	return c.JSON(out)
}

// mapCRDTErr maps the CRDT endpoints' specific errors, then falls back to
// mapErr.
func mapCRDTErr(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, errCRDTUnavailable):
		return c.Status(http.StatusServiceUnavailable).JSON(fiber.Map{"error": "crdt_unavailable"})
	case errors.Is(err, errBaseRequired):
		return c.Status(http.StatusConflict).JSON(fiber.Map{
			"error":  "base_required",
			"detail": "send base_state (from GET /snapshot `state`) so the server can merge instead of overwrite",
		})
	case errors.Is(err, crdt.ErrBaseUnreconstructable):
		return c.Status(http.StatusConflict).JSON(fiber.Map{
			"error":  "base_too_old",
			"detail": "base_state cannot be reconstructed; refetch GET /snapshot and redo the edit on it",
		})
	case errors.Is(err, crdt.ErrBaseMismatch):
		return c.Status(http.StatusConflict).JSON(fiber.Map{"error": "base_mismatch", "detail": err.Error()})
	}
	return mapErr(c, err)
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
