package pg

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// MemberStore persists vault membership rows.
type MemberStore struct {
	pool *pgxpool.Pool
}

func NewMemberStore(pool *pgxpool.Pool) *MemberStore {
	return &MemberStore{pool: pool}
}

func (s *MemberStore) Add(ctx context.Context, m domain.Member) error {
	const q = `
INSERT INTO vault_members (vault_id, user_id, role_id, joined_at)
VALUES ($1, $2, $3, $4)`
	if _, err := s.pool.Exec(ctx, q, m.VaultID, m.UserID, m.RoleID, m.JoinedAt); err != nil {
		return fmt.Errorf("member store: add: %w", errMap(err))
	}
	return nil
}

func (s *MemberStore) Remove(ctx context.Context, vaultID, userID uuid.UUID) error {
	const q = `DELETE FROM vault_members WHERE vault_id = $1 AND user_id = $2`
	tag, err := s.pool.Exec(ctx, q, vaultID, userID)
	if err != nil {
		return fmt.Errorf("member store: remove: %w", errMap(err))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("member store: remove: %w", domain.ErrNotFound)
	}
	return nil
}

func (s *MemberStore) ChangeRole(ctx context.Context, vaultID, userID, newRoleID uuid.UUID) error {
	const q = `
UPDATE vault_members
   SET role_id = $3
 WHERE vault_id = $1 AND user_id = $2`
	tag, err := s.pool.Exec(ctx, q, vaultID, userID, newRoleID)
	if err != nil {
		return fmt.Errorf("member store: change role: %w", errMap(err))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("member store: change role: %w", domain.ErrNotFound)
	}
	return nil
}

func (s *MemberStore) Get(ctx context.Context, vaultID, userID uuid.UUID) (domain.Member, error) {
	const q = `
SELECT vault_id, user_id, role_id, joined_at
  FROM vault_members
 WHERE vault_id = $1 AND user_id = $2`
	var m domain.Member
	err := s.pool.QueryRow(ctx, q, vaultID, userID).
		Scan(&m.VaultID, &m.UserID, &m.RoleID, &m.JoinedAt)
	if err != nil {
		if errors.Is(errMap(err), domain.ErrNotFound) {
			return domain.Member{}, fmt.Errorf("member store: get: %w", domain.ErrNotFound)
		}
		return domain.Member{}, fmt.Errorf("member store: get: %w", errMap(err))
	}
	return m, nil
}

// MemberJoined is the JOIN-resolved view used by ListForVault.
type MemberJoined struct {
	Member domain.Member
	User   domain.User
	Role   domain.Role
}

// ListForVault returns members joined with their user + role rows.
func (s *MemberStore) ListForVault(ctx context.Context, vaultID uuid.UUID) ([]MemberJoined, error) {
	const q = `
SELECT m.vault_id, m.user_id, m.role_id, m.joined_at,
       u.id, u.username, u.password_hash, u.display_name, u.created_at,
       r.id, r.vault_id, r.name, r.capabilities, r.is_seed
  FROM vault_members m
  JOIN users u ON u.id = m.user_id
  JOIN vault_roles r ON r.id = m.role_id
 WHERE m.vault_id = $1
 ORDER BY m.joined_at ASC`
	rows, err := s.pool.Query(ctx, q, vaultID)
	if err != nil {
		return nil, fmt.Errorf("member store: list: %w", errMap(err))
	}
	defer rows.Close()

	var out []MemberJoined
	for rows.Next() {
		var (
			mj   MemberJoined
			caps []byte
		)
		err := rows.Scan(
			&mj.Member.VaultID, &mj.Member.UserID, &mj.Member.RoleID, &mj.Member.JoinedAt,
			&mj.User.ID, &mj.User.Username, &mj.User.PasswordHash, &mj.User.DisplayName, &mj.User.CreatedAt,
			&mj.Role.ID, &mj.Role.VaultID, &mj.Role.Name, &caps, &mj.Role.IsSeed,
		)
		if err != nil {
			return nil, fmt.Errorf("member store: list scan: %w", err)
		}
		cs, err := unmarshalCaps(caps)
		if err != nil {
			return nil, fmt.Errorf("member store: list caps: %w", err)
		}
		mj.Role.Capabilities = cs
		out = append(out, mj)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("member store: list rows: %w", err)
	}
	return out, nil
}

// IsSoleAdmin reports whether the user is the only admin of a vault.
func (s *MemberStore) IsSoleAdmin(ctx context.Context, vaultID, userID uuid.UUID) (bool, error) {
	const q = `
SELECT
  EXISTS (
    SELECT 1 FROM vault_members vm
    JOIN vault_roles vr ON vr.id = vm.role_id
    WHERE vm.vault_id = $1 AND vm.user_id = $2
      AND vr.is_seed = TRUE AND vr.name = 'Admin'
  ) AS is_admin,
  (
    SELECT COUNT(*) FROM vault_members vm
    JOIN vault_roles vr ON vr.id = vm.role_id
    WHERE vm.vault_id = $1
      AND vr.is_seed = TRUE AND vr.name = 'Admin'
  ) AS admin_count`

	var isAdmin bool
	var adminCount int64
	if err := s.pool.QueryRow(ctx, q, vaultID, userID).Scan(&isAdmin, &adminCount); err != nil {
		return false, fmt.Errorf("member store: is sole admin: %w", errMap(err))
	}
	return isAdmin && adminCount == 1, nil
}

// RoleForUser returns the user's role in a vault via JOIN.
func (s *MemberStore) RoleForUser(ctx context.Context, vaultID, userID uuid.UUID) (domain.Role, error) {
	const q = `
SELECT vr.id, vr.vault_id, vr.name, vr.capabilities, vr.is_seed
  FROM vault_members vm
  JOIN vault_roles vr ON vr.id = vm.role_id
 WHERE vm.vault_id = $1 AND vm.user_id = $2`

	row := s.pool.QueryRow(ctx, q, vaultID, userID)
	r, err := scanRole(row)
	if err != nil {
		if errors.Is(errMap(err), domain.ErrNotFound) {
			return domain.Role{}, fmt.Errorf("member store: role for user: %w", domain.ErrNotFound)
		}
		return domain.Role{}, fmt.Errorf("member store: role for user: %w", errMap(err))
	}
	return r, nil
}
