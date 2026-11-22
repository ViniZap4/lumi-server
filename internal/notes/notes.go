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
	"context"
	"encoding/base64"
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
	"github.com/ViniZap4/lumi-server/internal/crdt"
	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/storage/fs"
	"github.com/ViniZap4/lumi-server/internal/wsync"
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
	now       func() time.Time
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
}

// SetLiveDocs wires the doc authority. Without it the CRDT write
// endpoints answer crdt_unavailable and PATCH body skips the CRDT.
func (s *Service) SetLiveDocs(d LiveDocs) { s.docs = d }

// CRDTInitBody returns a note's on-disk body for lazy CRDT seeding
// (crdt.InitSource). Unknown notes and notes without a file yet (e.g. a
// federation replica awaiting its first mirrored update) yield "".
func (s *Service) CRDTInitBody(ctx context.Context, vaultID uuid.UUID, noteID string) (string, error) {
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
	s.suppressFSEvent(v.Slug, relPath)
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

	// Seed the CRDT so live sync, /snapshot and /diff have a base state.
	// This server is the note's home, so it is the single seeder (§10 S5).
	// A failure rolls the create back: leaving a note whose CRDT is
	// unseeded would let the first live edit race lazy init.
	if s.crdt != nil {
		if err := s.crdt.InitFromText(ctx, vaultID, id, in.Body, in.Actor, "snapshot-init"); err != nil {
			_ = s.notes.Delete(ctx, vaultID, id)
			s.suppressFSEvent(v.Slug, relPath)
			_ = s.fs.DeleteNote(v.Slug, relPath)
			return domain.Note{}, fmt.Errorf("seed crdt: %w", err)
		}
	}
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
	}
	if !edited && !moved {
		return n, nil
	}
	if err := s.notes.Upsert(ctx, updated); err != nil {
		return domain.Note{}, err
	}
	// Path/title changes are metadata-only: the CRDT persist hook never
	// sees them, so federated peers need an explicit nudge.
	if (moved || newTitle != n.Title) && s.fedNotify != nil {
		s.fedNotify.NoteMoved(vaultID, id, newPath, newTitle)
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

// validateNoteRelPath normalises (trim + path.Clean) and then applies
// domain.ValidateNotePath: rejects absolute paths, parent traversals,
// hidden/dot segments, and any path that does not end in `.md`. fs.SafeJoin enforces the same plus
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
	if err := s.notes.Delete(ctx, vaultID, id); err != nil {
		return err
	}
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
	NoteID      string
	Path        string
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
	n, err := s.notes.Get(ctx, vaultID, id)
	if err != nil {
		return SnapshotResult{}, err
	}
	out := SnapshotResult{NoteID: n.ID, Path: n.Path}
	err = s.docs.View(ctx, vaultID, id, func(doc *crdt.Doc) error {
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
	return out, nil
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
	opts := wsync.ApplyOptions{Actor: actor, Origin: originKind, Mirror: wsync.MirrorNow}

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
		Actor: actor, Origin: originKind, Mirror: wsync.MirrorNow,
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
	return SnapshotResult{
		NoteID:      n.ID,
		Path:        n.Path,
		Text:        res.Text,
		VectorClock: res.StateVector,
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
	if err := s.fs.WriteNote(v.Slug, n.Path, front, []byte(text)); err != nil {
		return err
	}
	// Bump updated_at in pg so listings reflect the edit. No audit row
	// here — the underlying CRDT write is audited by its entry point.
	updated := n
	updated.UpdatedAt = now
	_ = s.notes.Upsert(ctx, updated)
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
	// CRDT TUI-style snapshot + diff sync — see SPEC.md "CRDT integration".
	r.Get("/vaults/:vault/notes/:id/snapshot",
		capguard.RequireCapability(resolver, domain.CapNoteRead),
		h.getSnapshot,
	)
	r.Post("/vaults/:vault/notes/:id/diff",
		capguard.RequireCapability(resolver, domain.CapNoteEdit),
		h.applyDiff,
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

// getSnapshot — GET /api/vaults/:vault/notes/:id/snapshot
//
// Returns { id, path, text, vector_clock, state }:
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
		"text":         r.Text,
		"vector_clock": base64.StdEncoding.EncodeToString(r.VectorClock),
		"state":        base64.StdEncoding.EncodeToString(r.State),
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
// (base_state is not an ancestor of the server's state).
// Success: { id, path, text, vector_clock }.
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
	return c.JSON(fiber.Map{
		"id":           r.NoteID,
		"path":         r.Path,
		"text":         r.Text,
		"vector_clock": base64.StdEncoding.EncodeToString(r.VectorClock),
	})
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
