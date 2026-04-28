package pg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// UserStore is the persistence boundary for users.
type UserStore struct {
	pool *pgxpool.Pool
}

// NewUserStore wires a UserStore against the supplied pool.
func NewUserStore(pool *pgxpool.Pool) *UserStore {
	return &UserStore{pool: pool}
}

// CreateUserInput satisfies internal/auth.CreateUserInput shape.
type CreateUserInput struct {
	Username     string
	PasswordHash string
	DisplayName  string
}

// Create inserts a new user. Returns domain.ErrConflict if the username is
// already taken.
func (s *UserStore) Create(ctx context.Context, u domain.User) error {
	const q = `
INSERT INTO users (id, username, password_hash, display_name, created_at)
VALUES ($1, $2, $3, $4, $5)`
	_, err := s.pool.Exec(ctx, q,
		u.ID, u.Username, u.PasswordHash, u.DisplayName, u.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("user store: create: %w", errMap(err))
	}
	return nil
}

// CreateUser is the input-struct variant matching internal/auth.UserRepo.
// Generates id and created_at server-side.
func (s *UserStore) CreateUser(ctx context.Context, in CreateUserInput) (domain.User, error) {
	u := domain.User{
		ID:           uuid.New(),
		Username:     in.Username,
		PasswordHash: in.PasswordHash,
		DisplayName:  in.DisplayName,
		CreatedAt:    time.Now().UTC(),
	}
	if err := s.Create(ctx, u); err != nil {
		return domain.User{}, err
	}
	return u, nil
}

// CreateUserDirect is the (User) error variant matching internal/invites.UserRepo.
func (s *UserStore) CreateUserDirect(ctx context.Context, u domain.User) error {
	return s.Create(ctx, u)
}

func (s *UserStore) GetByID(ctx context.Context, id uuid.UUID) (domain.User, error) {
	const q = `
SELECT id, username, password_hash, display_name, created_at
  FROM users
 WHERE id = $1`
	return s.scanOne(ctx, q, id)
}

func (s *UserStore) GetByUsername(ctx context.Context, username string) (domain.User, error) {
	const q = `
SELECT id, username, password_hash, display_name, created_at
  FROM users
 WHERE username = $1`
	return s.scanOne(ctx, q, username)
}

func (s *UserStore) UpdateDisplayName(ctx context.Context, id uuid.UUID, name string) error {
	const q = `UPDATE users SET display_name = $2 WHERE id = $1`
	tag, err := s.pool.Exec(ctx, q, id, name)
	if err != nil {
		return fmt.Errorf("user store: update display name: %w", errMap(err))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user store: update display name: %w", domain.ErrNotFound)
	}
	return nil
}

// UpdatePassword writes a new hash. Alias: UpdatePasswordHash.
func (s *UserStore) UpdatePassword(ctx context.Context, id uuid.UUID, newHash string) error {
	const q = `UPDATE users SET password_hash = $2 WHERE id = $1`
	tag, err := s.pool.Exec(ctx, q, id, newHash)
	if err != nil {
		return fmt.Errorf("user store: update password: %w", errMap(err))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user store: update password: %w", domain.ErrNotFound)
	}
	return nil
}

// UpdatePasswordHash is the alias matching internal/auth.UserRepo.
func (s *UserStore) UpdatePasswordHash(ctx context.Context, id uuid.UUID, newHash string) error {
	return s.UpdatePassword(ctx, id, newHash)
}

// CountUsers is used by the auth bootstrap routine to detect first-run state.
func (s *UserStore) CountUsers(ctx context.Context) (int, error) {
	const q = `SELECT COUNT(*) FROM users`
	var n int
	if err := s.pool.QueryRow(ctx, q).Scan(&n); err != nil {
		return 0, fmt.Errorf("user store: count: %w", errMap(err))
	}
	return n, nil
}

// SoleAdminVaultIDs returns vault IDs for which the user is the sole member
// holding the seed Admin role.
func (s *UserStore) SoleAdminVaultIDs(ctx context.Context, id uuid.UUID) ([]uuid.UUID, error) {
	const q = `
SELECT vm.vault_id
  FROM vault_members vm
  JOIN vault_roles vr ON vr.id = vm.role_id
 WHERE vm.user_id = $1
   AND vr.is_seed = TRUE
   AND vr.name = 'Admin'
   AND NOT EXISTS (
       SELECT 1
         FROM vault_members vm2
         JOIN vault_roles vr2 ON vr2.id = vm2.role_id
        WHERE vm2.vault_id = vm.vault_id
          AND vm2.user_id <> vm.user_id
          AND vr2.is_seed = TRUE
          AND vr2.name = 'Admin'
   )`
	rows, err := s.pool.Query(ctx, q, id)
	if err != nil {
		return nil, fmt.Errorf("user store: sole admin vaults: %w", errMap(err))
	}
	defer rows.Close()

	var ids []uuid.UUID
	for rows.Next() {
		var v uuid.UUID
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("user store: sole admin vaults scan: %w", err)
		}
		ids = append(ids, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("user store: sole admin vaults rows: %w", err)
	}
	return ids, nil
}

// Delete erases a user. LGPD-aware: anonymises audit_log rows in the same tx.
func (s *UserStore) Delete(ctx context.Context, id uuid.UUID, forceDeleteSoleAdminVaults bool) error {
	return runTx(ctx, s.pool, func(tx pgx.Tx) error {
		soleAdminVaults, err := soleAdminVaultIDsTx(ctx, tx, id)
		if err != nil {
			return fmt.Errorf("user store: delete: sole admin probe: %w", err)
		}
		if len(soleAdminVaults) > 0 {
			if !forceDeleteSoleAdminVaults {
				return fmt.Errorf("user store: delete: %w", domain.ErrSoleAdminVaults)
			}
			if _, err := tx.Exec(ctx,
				`DELETE FROM vaults WHERE id = ANY($1)`, soleAdminVaults,
			); err != nil {
				return fmt.Errorf("user store: delete: force vaults: %w", errMap(err))
			}
		}

		if err := anonymiseUserAuditTx(ctx, tx, id); err != nil {
			return fmt.Errorf("user store: delete: anonymise audit: %w", err)
		}

		tag, err := tx.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
		if err != nil {
			return fmt.Errorf("user store: delete: %w", errMap(err))
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("user store: delete: %w", domain.ErrNotFound)
		}
		return nil
	})
}

func soleAdminVaultIDsTx(ctx context.Context, tx pgx.Tx, id uuid.UUID) ([]uuid.UUID, error) {
	const q = `
SELECT vm.vault_id
  FROM vault_members vm
  JOIN vault_roles vr ON vr.id = vm.role_id
 WHERE vm.user_id = $1
   AND vr.is_seed = TRUE
   AND vr.name = 'Admin'
   AND NOT EXISTS (
       SELECT 1
         FROM vault_members vm2
         JOIN vault_roles vr2 ON vr2.id = vm2.role_id
        WHERE vm2.vault_id = vm.vault_id
          AND vm2.user_id <> vm.user_id
          AND vr2.is_seed = TRUE
          AND vr2.name = 'Admin'
   )`
	rows, err := tx.Query(ctx, q, id)
	if err != nil {
		return nil, errMap(err)
	}
	defer rows.Close()

	var ids []uuid.UUID
	for rows.Next() {
		var v uuid.UUID
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		ids = append(ids, v)
	}
	return ids, rows.Err()
}

func (s *UserStore) scanOne(ctx context.Context, q string, args ...any) (domain.User, error) {
	var u domain.User
	err := s.pool.QueryRow(ctx, q, args...).Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.DisplayName, &u.CreatedAt,
	)
	if err != nil {
		if errors.Is(errMap(err), domain.ErrNotFound) {
			return domain.User{}, fmt.Errorf("user store: %w", domain.ErrNotFound)
		}
		return domain.User{}, fmt.Errorf("user store: get: %w", errMap(err))
	}
	return u, nil
}
