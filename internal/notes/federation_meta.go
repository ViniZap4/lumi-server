// Frontmatter replication over federation links (G1,
// docs/SPEC-ESPELHO-SELADO.md §A4.2 frameNoteMeta2).
package notes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// maxFederatedFrontmatter mirrors the relay's frame cap.
const maxFederatedFrontmatter = 16 << 10

// derivedFrontKeys are computed by each server (id and title from the
// note row, updated_at from local writes) and never replicated.
var derivedFrontKeys = map[string]bool{"id": true, "title": true, "updated_at": true}

// MetaNotifier is the optional FederationNotifier extension for
// frontmatter changes (tags, created_at, unknown keys).
type MetaNotifier interface {
	NoteMetaChanged(vaultID uuid.UUID, noteID string)
}

// notifyMetaChanged tells the relay a note's frontmatter changed.
func (s *Service) notifyMetaChanged(vaultID uuid.UUID, noteID string) {
	if mn, ok := s.fedNotify.(MetaNotifier); ok {
		mn.NoteMetaChanged(vaultID, noteID)
	}
}

// NotifyMetaChanged is called by the fs-watcher handler after an external
// edit: the file's frontmatter may have changed.
func (s *Service) NotifyMetaChanged(vaultID uuid.UUID, noteID string) {
	s.notifyMetaChanged(vaultID, noteID)
}

// replicatedFront returns the non-derived keys of a frontmatter map as
// JSON-compatible values.
func replicatedFront(front map[string]any) map[string]any {
	out := make(map[string]any, len(front))
	for k, v := range front {
		if derivedFrontKeys[k] {
			continue
		}
		out[k] = yamlToJSON(v)
	}
	return out
}

// FrontmatterForFederation returns the note's replicated frontmatter as a
// JSON object, or nil when there is nothing to send (canvas notes have no
// frontmatter; a note whose file has not landed yet has none either).
func (s *Service) FrontmatterForFederation(ctx context.Context, vaultID uuid.UUID, noteID string) ([]byte, error) {
	n, err := s.notes.Get(ctx, vaultID, noteID)
	if err != nil {
		return nil, err
	}
	if domain.IsCanvasPath(n.Path) {
		return nil, nil
	}
	v, err := s.vaults.GetByID(ctx, vaultID)
	if err != nil {
		return nil, err
	}
	front, _, err := s.fs.ReadNote(v.Slug, n.Path)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	b, err := json.Marshal(replicatedFront(front))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFederatedFrontmatter {
		return nil, fmt.Errorf("%w: frontmatter of %q exceeds %d bytes", domain.ErrValidation, noteID, maxFederatedFrontmatter)
	}
	return b, nil
}

// ApplyFrontmatterFromFederation replaces the note's replicated
// frontmatter keys with the ones a peer sent: every non-derived key not in
// the document is removed, so the operation is idempotent. id, title and
// updated_at stay local. A created_at the peer sends also becomes the
// row's created_at. Nothing is written when nothing changes. Does not
// notify the relay (it fans the frame onward itself).
func (s *Service) ApplyFrontmatterFromFederation(ctx context.Context, vaultID uuid.UUID, noteID string, frontmatterJSON []byte) error {
	if len(frontmatterJSON) > maxFederatedFrontmatter {
		return fmt.Errorf("%w: frontmatter too large", domain.ErrValidation)
	}
	var incoming map[string]any
	dec := json.NewDecoder(bytes.NewReader(frontmatterJSON))
	dec.UseNumber()
	if err := dec.Decode(&incoming); err != nil || incoming == nil {
		return fmt.Errorf("%w: frontmatter must be a JSON object", domain.ErrValidation)
	}
	for k := range incoming {
		if k == "" || len(k) > 256 {
			return fmt.Errorf("%w: invalid frontmatter key", domain.ErrValidation)
		}
	}
	n, err := s.notes.Get(ctx, vaultID, noteID)
	if err != nil {
		return err
	}
	if domain.IsCanvasPath(n.Path) {
		return nil
	}
	v, err := s.vaults.GetByID(ctx, vaultID)
	if err != nil {
		return err
	}
	front, body, err := s.fs.ReadNote(v.Slug, n.Path)
	if err != nil {
		if !errors.Is(err, domain.ErrNotFound) {
			return err
		}
		// Content has not landed yet: write the frontmatter now, the
		// first mirrored update keeps it.
		front, body = map[string]any{"id": noteID, "title": n.Title}, nil
	}
	cur, _ := json.Marshal(replicatedFront(front))
	want := map[string]any{}
	for k, val := range incoming {
		if !derivedFrontKeys[k] {
			want[k] = normalizeJSONNumber(val)
		}
	}
	wantJSON, _ := json.Marshal(want)
	if bytes.Equal(cur, wantJSON) {
		return nil
	}
	next := make(map[string]any, len(want)+3)
	for k := range derivedFrontKeys {
		if val, ok := front[k]; ok {
			next[k] = val
		}
	}
	if _, ok := next["id"]; !ok {
		next["id"] = noteID
	}
	for k, val := range want {
		next[k] = val
	}
	s.suppressFSEvent(v.Slug, n.Path)
	if err := s.fs.WriteNote(v.Slug, n.Path, next, body); err != nil {
		return err
	}
	// The original creation time also becomes the row's (lists sort and
	// show it), when the store supports rewriting it.
	if raw, ok := want["created_at"].(string); ok {
		if at, err := time.Parse(time.RFC3339, raw); err == nil && !at.Equal(n.CreatedAt) {
			if cs, ok := s.notes.(CreatedAtSetter); ok {
				if err := cs.SetCreatedAt(ctx, vaultID, noteID, at.UTC()); err != nil {
					return err
				}
			}
		}
	}
	// Clients learn about the change through the vault seq, as for a
	// local tags edit.
	updated, err := s.notes.Get(ctx, vaultID, noteID)
	if err != nil {
		return err
	}
	updated.UpdatedAt = s.now().UTC()
	return s.upsertMeta(ctx, updated)
}

// CreatedAtSetter is the optional NoteRepo extension that rewrites a
// note's created_at (Upsert never does). Implemented by pg.NoteStore.
type CreatedAtSetter interface {
	SetCreatedAt(ctx context.Context, vaultID uuid.UUID, id string, at time.Time) error
}

// normalizeJSONNumber turns json.Number values into int64 or float64 so
// the YAML encoder writes plain numbers.
func normalizeJSONNumber(v any) any {
	switch t := v.(type) {
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i
		}
		if f, err := t.Float64(); err == nil {
			return f
		}
		return t.String()
	case map[string]any:
		for k, val := range t {
			t[k] = normalizeJSONNumber(val)
		}
		return t
	case []any:
		for i, val := range t {
			t[i] = normalizeJSONNumber(val)
		}
		return t
	default:
		return v
	}
}
