package invites

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

type memRepo struct{ created []domain.Invite }

func (m *memRepo) Create(_ context.Context, inv domain.Invite) error {
	m.created = append(m.created, inv)
	return nil
}
func (m *memRepo) Get(context.Context, string) (domain.Invite, error) {
	return domain.Invite{}, domain.ErrNotFound
}
func (m *memRepo) IncrementUse(context.Context, string, time.Time) (domain.Invite, error) {
	return domain.Invite{}, domain.ErrNotFound
}
func (m *memRepo) Revoke(context.Context, string, time.Time) error { return nil }
func (m *memRepo) ListForVault(context.Context, uuid.UUID) ([]domain.Invite, error) {
	return nil, nil
}

type nopUsers struct{}

func (nopUsers) GetByUsername(context.Context, string) (domain.User, error) {
	return domain.User{}, domain.ErrNotFound
}
func (nopUsers) CreateUserDirect(context.Context, domain.User) error { return nil }

type nopMembers struct{}

func (nopMembers) Add(context.Context, domain.Member) error { return nil }
func (nopMembers) Get(context.Context, uuid.UUID, uuid.UUID) (domain.Member, error) {
	return domain.Member{}, domain.ErrNotFound
}

type mapVaults map[uuid.UUID]domain.Vault

func (m mapVaults) GetByID(_ context.Context, id uuid.UUID) (domain.Vault, error) {
	v, ok := m[id]
	if !ok {
		return domain.Vault{}, domain.ErrNotFound
	}
	return v, nil
}
func (m mapVaults) GetBySlug(context.Context, string) (domain.Vault, error) {
	return domain.Vault{}, domain.ErrNotFound
}

type mapRoles map[uuid.UUID]domain.Role

func (m mapRoles) GetByID(_ context.Context, id uuid.UUID) (domain.Role, error) {
	r, ok := m[id]
	if !ok {
		return domain.Role{}, domain.ErrNotFound
	}
	return r, nil
}

type nopConsents struct{}

func (nopConsents) Record(context.Context, domain.Consent) error { return nil }

type nopSessions struct{}

func (nopSessions) Create(context.Context, domain.Session) error { return nil }

type nopHasher struct{}

func (nopHasher) HashPassword(string) (string, error) { return "x", nil }

type nopTokens struct{}

func (nopTokens) NewSessionToken() string { return "t" }

type userRoles map[uuid.UUID]domain.Role

func (u userRoles) RoleForUser(_ context.Context, _ uuid.UUID, userID uuid.UUID) (domain.Role, error) {
	r, ok := u[userID]
	if !ok {
		return domain.Role{}, domain.ErrNotFound
	}
	return r, nil
}

// TestCreate_NoEscalation is the regression test for members.invite
// minting Admin invites.
func TestCreate_NoEscalation(t *testing.T) {
	vaultID, owner, inviter := uuid.New(), uuid.New(), uuid.New()
	admin := domain.Role{ID: uuid.New(), VaultID: vaultID, Name: "Admin", IsSeed: true,
		Capabilities: domain.CapabilitySet{domain.CapAll}}
	viewer := domain.Role{ID: uuid.New(), VaultID: vaultID, Name: "Viewer", IsSeed: true,
		Capabilities: domain.CapabilitySet{domain.CapNoteRead}}
	inviterRole := domain.Role{ID: uuid.New(), VaultID: vaultID, Name: "Inviter",
		Capabilities: domain.CapabilitySet{domain.CapMembersInvite, domain.CapNoteRead}}
	foreign := domain.Role{ID: uuid.New(), VaultID: uuid.New(), Name: "Admin",
		Capabilities: domain.CapabilitySet{domain.CapAll}}

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cases := []struct {
		name     string
		actor    uuid.UUID
		role     uuid.UUID
		resolver bool
		wantErr  error
	}{
		{"inviter mints admin invite", inviter, admin.ID, true, domain.ErrForbidden},
		{"inviter mints viewer invite", inviter, viewer.ID, true, nil},
		{"owner mints admin invite", owner, admin.ID, true, nil},
		{"foreign role", owner, foreign.ID, true, domain.ErrValidation},
		{"no resolver: non-owner denied", inviter, viewer.ID, false, domain.ErrForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := &memRepo{}
			d := Deps{
				Repo:     repo,
				Users:    nopUsers{},
				Members:  nopMembers{},
				Vaults:   mapVaults{vaultID: {ID: vaultID, OwnerUserID: owner}},
				Roles:    mapRoles{admin.ID: admin, viewer.ID: viewer, inviterRole.ID: inviterRole, foreign.ID: foreign},
				Consents: nopConsents{},
				Sessions: nopSessions{},
				Hasher:   nopHasher{},
				Tokens:   nopTokens{},
				Now:      func() time.Time { return now },
			}
			if tc.resolver {
				d.Resolver = userRoles{inviter: inviterRole, owner: admin}
			}
			svc := NewService(d)
			_, err := svc.Create(context.Background(), CreateInput{
				VaultID: vaultID, RoleID: tc.role, InviterID: tc.actor,
				MaxUses: 1, ExpiresAt: now.Add(24 * time.Hour),
			})
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(repo.created) != 1 {
					t.Fatalf("invite not persisted")
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got %v, want %v", err, tc.wantErr)
			}
			if len(repo.created) != 0 {
				t.Fatalf("invite persisted despite error")
			}
		})
	}
}
