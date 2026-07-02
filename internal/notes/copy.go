// Share-a-copy support (v3 Phase O): fork every note of one vault into
// another. Called by vaults.Service.CopyToUser; capability enforcement and
// destination-vault provisioning happen there.
package notes

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// copyPageSize bounds each metadata page while walking the source vault.
const copyPageSize = 200

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
			if err := s.notes.Upsert(ctx, row); err != nil {
				return copied, fmt.Errorf("copy: upsert %q: %w", n.ID, err)
			}
			if s.crdt != nil {
				if err := s.crdt.InitFromText(ctx, dstVaultID, n.ID, string(body), actor, "vault-copy"); err != nil {
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
