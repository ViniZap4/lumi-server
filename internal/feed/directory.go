package feed

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/vaults"
)

// ViewSource is the vault listing the feed builds on (*vaults.Service):
// membership + federation-aware role + head, the same data GET
// /api/vaults serves.
type ViewSource interface {
	ListViews(ctx context.Context, userID uuid.UUID) ([]vaults.View, error)
	GetView(ctx context.Context, userID, vaultID uuid.UUID) (vaults.View, error)
}

// VaultsDirectory is the production Directory: a vault is readable iff
// the caller's resolved role has note.read.
type VaultsDirectory struct {
	Source ViewSource
}

func toAccess(v vaults.View) VaultAccess {
	return VaultAccess{VaultID: v.Vault.ID, Seq: v.Head, Role: v.Role.Name, CanEdit: v.CanEdit()}
}

func (d VaultsDirectory) Readable(ctx context.Context, userID uuid.UUID) ([]VaultAccess, error) {
	views, err := d.Source.ListViews(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]VaultAccess, 0, len(views))
	for _, v := range views {
		if v.CanRead() {
			out = append(out, toAccess(v))
		}
	}
	return out, nil
}

func (d VaultsDirectory) Access(ctx context.Context, userID, vaultID uuid.UUID) (VaultAccess, bool, error) {
	v, err := d.Source.GetView(ctx, userID, vaultID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return VaultAccess{}, false, nil
		}
		return VaultAccess{}, false, err
	}
	if !v.CanRead() {
		return VaultAccess{}, false, nil
	}
	return toAccess(v), true, nil
}
