package capguard

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

type mapResolver map[uuid.UUID]domain.Role

func (m mapResolver) RoleForUser(_ context.Context, _ uuid.UUID, userID uuid.UUID) (domain.Role, error) {
	r, ok := m[userID]
	if !ok {
		return domain.Role{}, domain.ErrNotFound
	}
	return r, nil
}

func TestAuthorizeGrant(t *testing.T) {
	vaultID, owner, inviter, manager, stranger := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
	vault := domain.Vault{ID: vaultID, OwnerUserID: owner}
	admin := domain.Role{ID: uuid.New(), VaultID: vaultID, Name: "Admin", Capabilities: domain.CapabilitySet{domain.CapAll}}
	editor := domain.Role{ID: uuid.New(), VaultID: vaultID, Name: "Editor", Capabilities: domain.CapabilitySet{domain.CapNoteRead, domain.CapNoteEdit}}
	viewer := domain.Role{ID: uuid.New(), VaultID: vaultID, Name: "Viewer", Capabilities: domain.CapabilitySet{domain.CapNoteRead}}
	inviterRole := domain.Role{ID: uuid.New(), VaultID: vaultID, Capabilities: domain.CapabilitySet{domain.CapMembersInvite, domain.CapNoteRead}}
	managerRole := domain.Role{ID: uuid.New(), VaultID: vaultID, Capabilities: domain.CapabilitySet{domain.CapMembersManage, domain.CapNoteAll}}
	foreign := domain.Role{ID: uuid.New(), VaultID: uuid.New(), Capabilities: domain.CapabilitySet{domain.CapNoteRead}}

	res := mapResolver{inviter: inviterRole, manager: managerRole}

	cases := []struct {
		name    string
		actor   uuid.UUID
		target  domain.Role
		r       Resolver
		wantErr error
	}{
		{"owner grants admin", owner, admin, res, nil},
		{"owner exempt even without resolver", owner, admin, nil, nil},
		{"inviter grants viewer", inviter, viewer, res, nil},
		{"inviter cannot grant admin", inviter, admin, res, domain.ErrForbidden},
		{"inviter cannot grant editor", inviter, editor, res, domain.ErrForbidden},
		{"manager grants editor", manager, editor, res, nil},
		{"manager cannot grant admin", manager, admin, res, domain.ErrForbidden},
		{"non-member", stranger, viewer, res, domain.ErrForbidden},
		{"no resolver fails closed", inviter, viewer, nil, domain.ErrForbidden},
		{"foreign role rejected even for owner", owner, foreign, res, domain.ErrValidation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := AuthorizeGrant(context.Background(), tc.r, vault, tc.actor, tc.target)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
}
