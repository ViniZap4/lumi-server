// Share-a-copy support (v3 Phase O): fork every note of one vault into
// another. Called by vaults.Service.CopyToUser; capability enforcement and
// destination-vault provisioning happen there.
package notes

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// copyPageSize bounds each metadata page while walking the source vault.
const copyPageSize = 200

// CreateFromFederation inserts the metadata row for a note announced by a
// federated peer (the file lands with the first mirrored update). Bumps
// the local vault seq like any other create. Idempotent: an existing row
// is left alone.
//
// n.CRDTEpoch carries the announcing peer's epoch when it sent one: the
// local row then names the same CRDT history the peer's doc belongs to
// (the state arrives over the relay; this server never seeds it). An
// existing row is left untouched, epoch included.
func (s *Service) CreateFromFederation(ctx context.Context, n domain.Note) error {
	if _, err := s.notes.Get(ctx, n.VaultID, n.ID); err == nil {
		return nil
	} else if !errors.Is(err, domain.ErrNotFound) {
		return err
	}
	return s.upsertMeta(ctx, n)
}

// MoveFromFederation applies a rename/move relayed from a federated peer:
// row + file update, no notifier re-fire (the relay fans it onward itself).
// Tolerant of a missing source file (the mirrored content may not have
// landed yet) and idempotent when the note already matches.
func (s *Service) MoveFromFederation(ctx context.Context, vaultID uuid.UUID, id, newPath, newTitle string) error {
	cleaned, err := validateNoteRelPath(newPath)
	if err != nil {
		return err
	}
	n, err := s.notes.Get(ctx, vaultID, id)
	if err != nil {
		return err
	}
	v, err := s.vaults.GetByID(ctx, vaultID)
	if err != nil {
		return err
	}
	title := strings.TrimSpace(newTitle)
	if title == "" {
		title = n.Title
	}
	if cleaned == n.Path && title == n.Title {
		return nil
	}
	if cleaned != n.Path {
		if other, err := s.notes.GetByPath(ctx, vaultID, cleaned); err == nil && other.ID != id {
			return fmt.Errorf("%w: path %q already exists", domain.ErrConflict, cleaned)
		}
		s.suppressFSEvent(v.Slug, n.Path)
		s.suppressFSEvent(v.Slug, cleaned)
		if err := s.fs.MoveNote(v.Slug, n.Path, cleaned); err != nil && !errors.Is(err, domain.ErrNotFound) {
			return err
		}
	}
	updated := n
	updated.Path = cleaned
	updated.Title = title
	updated.UpdatedAt = s.now().UTC()
	if err := s.upsertMeta(ctx, updated); err != nil {
		return err
	}
	s.recordAudit(ctx, uuid.Nil, vaultID, domain.ActionNoteMove, "", "", map[string]any{
		"note_id":  id,
		"old_path": n.Path,
		"new_path": cleaned,
		"origin":   "federation",
	})
	return nil
}

// CopyVaultNotes copies file content, note metadata rows, and CRDT seed
// state from srcVaultID into dstVaultID. Note IDs and relative paths are
// preserved (they are vault-scoped), timestamps carry over verbatim so the
// copy is a faithful snapshot. Returns the number of notes copied; on error
// the caller rolls the destination vault back, so partial state is fine.
func (s *Service) CopyVaultNotes(ctx context.Context, srcVaultID, dstVaultID, actor uuid.UUID) (int, error) {
	src, err := s.vaults.GetByID(ctx, srcVaultID)
	if err != nil {
		return 0, fmt.Errorf("copy: source vault: %w", err)
	}
	dst, err := s.vaults.GetByID(ctx, dstVaultID)
	if err != nil {
		return 0, fmt.Errorf("copy: destination vault: %w", err)
	}

	copied := 0
	for offset := 0; ; offset += copyPageSize {
		batch, err := s.notes.ListForVault(ctx, srcVaultID, copyPageSize, offset)
		if err != nil {
			return copied, fmt.Errorf("copy: list notes: %w", err)
		}
		for _, n := range batch {
			front, body, err := s.fs.ReadNote(src.Slug, n.Path)
			if err != nil {
				return copied, fmt.Errorf("copy: read %q: %w", n.Path, err)
			}
			// The write below is our own: keep the FS watcher from
			// bouncing it back into the CRDT as an "external" edit.
			s.suppressFSEvent(dst.Slug, n.Path)
			if err := s.fs.WriteNote(dst.Slug, n.Path, front, body); err != nil {
				return copied, fmt.Errorf("copy: write %q: %w", n.Path, err)
			}
			row := n
			row.VaultID = dstVaultID
			// The copy is seeded from text: a new CRDT history, so a new
			// epoch (never the source note's).
			row.CRDTEpoch = domain.NewCRDTEpoch()
			if err := s.upsertMeta(ctx, row); err != nil {
				return copied, fmt.Errorf("copy: upsert %q: %w", n.ID, err)
			}
			if s.crdt != nil {
				if _, err := s.crdt.InitFromTextEpoch(ctx, dstVaultID, n.ID, string(body), row.CRDTEpoch, actor, "vault-copy"); err != nil {
					return copied, fmt.Errorf("copy: crdt init %q: %w", n.ID, err)
				}
			}
			copied++
		}
		if len(batch) < copyPageSize {
			return copied, nil
		}
	}
}
