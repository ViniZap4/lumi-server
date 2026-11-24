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

const userCols = `id, username, password_hash, display_name, created_at, disabled_at, failed_logins, locked_until, server_admin`

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
	q := `
SELECT ` + userCols + `
  FROM users
 WHERE id = $1`
	return s.scanOne(ctx, q, id)
}

func (s *UserStore) GetByUsername(ctx context.Context, username string) (domain.User, error) {
	q := `
SELECT ` + userCols + `
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

// OwnedVaults returns the vaults the user owns. v3 Phase O re-keys the LGPD
// erasure guard on ownership: owned vaults must be transferred or explicitly
// force-deleted before the account can be erased.
func (s *UserStore) OwnedVaults(ctx context.Context, id uuid.UUID) ([]domain.Vault, error) {
	const q = `
SELECT id, slug, name, created_by, owner_user_id, copied_from, created_at
  FROM vaults
 WHERE owner_user_id = $1
 ORDER BY name ASC`
	rows, err := s.pool.Query(ctx, q, id)
	if err != nil {
		return nil, fmt.Errorf("user store: owned vaults: %w", errMap(err))
	}
	defer rows.Close()

	var out []domain.Vault
	for rows.Next() {
		v, err := scanVault(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("user store: owned vaults scan: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("user store: owned vaults rows: %w", err)
	}
	return out, nil
}

// Delete erases a user. LGPD-aware: anonymises audit_log rows in the same tx.
// The vault guard is owner-based (v3 Phase O): owned vaults block erasure
// unless forceDeleteOwnedVaults opts into deleting them.
func (s *UserStore) Delete(ctx context.Context, id uuid.UUID, forceDeleteOwnedVaults bool) error {
	return runTx(ctx, s.pool, func(tx pgx.Tx) error {
		ownedVaults, err := ownedVaultIDsTx(ctx, tx, id)
		if err != nil {
			return fmt.Errorf("user store: delete: owned-vault probe: %w", err)
		}
		if len(ownedVaults) > 0 {
			if !forceDeleteOwnedVaults {
				return fmt.Errorf("user store: delete: %w", domain.ErrSoleAdminVaults)
			}
			if _, err := tx.Exec(ctx,
				`DELETE FROM vaults WHERE id = ANY($1)`, ownedVaults,
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

func ownedVaultIDsTx(ctx context.Context, tx pgx.Tx, id uuid.UUID) ([]uuid.UUID, error) {
	rows, err := tx.Query(ctx, `SELECT id FROM vaults WHERE owner_user_id = $1`, id)
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
		&u.DisabledAt, &u.FailedLogins, &u.LockedUntil, &u.ServerAdmin,
	)
	if err != nil {
		if errors.Is(errMap(err), domain.ErrNotFound) {
			return domain.User{}, fmt.Errorf("user store: %w", domain.ErrNotFound)
		}
		return domain.User{}, fmt.Errorf("user store: get: %w", errMap(err))
	}
	return u, nil
}

// CountServerAdmins counts the accounts flagged server_admin (bootstrap).
func (s *UserStore) CountServerAdmins(ctx context.Context) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE server_admin`).Scan(&n); err != nil {
		return 0, fmt.Errorf("user store: count server admins: %w", errMap(err))
	}
	return n, nil
}

// GrantServerAdmin sets the server_admin flag and writes the audit row in
// the same transaction (bootstrap; the operator paths go through
// AdminStore.SetServerAdmin).
func (s *UserStore) GrantServerAdmin(ctx context.Context, id uuid.UUID, e domain.AuditEntry) error {
	return runTx(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE users SET server_admin = true WHERE id = $1`, id)
		if err != nil {
			return fmt.Errorf("user store: grant server admin: %w", errMap(err))
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("user store: grant server admin: %w", domain.ErrNotFound)
		}
		return insertAudit(ctx, tx, e)
	})
}

// RecordLoginFailure counts one wrong password for an existing account.
// Once failed_logins reaches threshold, locked_until is pushed out by
// 2^(n-threshold) seconds, capped at maxLock: the lock never becomes
// permanent, so an attacker cannot keep the owner out for longer than the
// cap after stopping. Attempts that arrive while the account is locked
// are refused before the password is checked and never reach here.
func (s *UserStore) RecordLoginFailure(ctx context.Context, id uuid.UUID, threshold int, maxLock time.Duration) error {
	const q = `
UPDATE users SET
  failed_logins = LEAST(failed_logins + 1, 1000),
  locked_until = CASE WHEN failed_logins + 1 >= $2
    THEN NOW() + make_interval(secs => LEAST(power(2, LEAST(failed_logins + 1 - $2, 20)), $3))
    ELSE locked_until END
 WHERE id = $1`
	if _, err := s.pool.Exec(ctx, q, id, threshold, maxLock.Seconds()); err != nil {
		return fmt.Errorf("user store: record login failure: %w", errMap(err))
	}
	return nil
}

// ResetLoginFailures clears the lockout counters after a successful login.
func (s *UserStore) ResetLoginFailures(ctx context.Context, id uuid.UUID) error {
	const q = `
UPDATE users SET failed_logins = 0, locked_until = NULL
 WHERE id = $1 AND (failed_logins <> 0 OR locked_until IS NOT NULL)`
	if _, err := s.pool.Exec(ctx, q, id); err != nil {
		return fmt.Errorf("user store: reset login failures: %w", errMap(err))
	}
	return nil
}
