package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// RoleStore persists per-vault roles. Capabilities are stored as JSONB.
type RoleStore struct {
	pool *pgxpool.Pool
}

func NewRoleStore(pool *pgxpool.Pool) *RoleStore {
	return &RoleStore{pool: pool}
}

// Create inserts a custom (non-seed) role and returns the persisted row.
func (s *RoleStore) Create(ctx context.Context, r domain.Role) (domain.Role, error) {
	if r.ID == uuid.Nil {
		r.ID = uuid.New()
	}
	caps, err := marshalCaps(r.Capabilities)
	if err != nil {
		return domain.Role{}, fmt.Errorf("role store: create: marshal caps: %w", err)
	}
	const q = `
INSERT INTO vault_roles (id, vault_id, name, capabilities, is_seed)
VALUES ($1, $2, $3, $4::jsonb, $5)`
	if _, err := s.pool.Exec(ctx, q, r.ID, r.VaultID, r.Name, caps, r.IsSeed); err != nil {
		return domain.Role{}, fmt.Errorf("role store: create: %w", errMap(err))
	}
	return r, nil
}

// Get returns a single role by (vault, role) id pair.
func (s *RoleStore) Get(ctx context.Context, vaultID, roleID uuid.UUID) (domain.Role, error) {
	const q = `
SELECT id, vault_id, name, capabilities, is_seed
  FROM vault_roles
 WHERE vault_id = $1 AND id = $2`
	return s.scanOne(ctx, q, vaultID, roleID)
}

// GetByID returns a single role by id only (used by invites where vault scope
// is verified separately).
func (s *RoleStore) GetByID(ctx context.Context, roleID uuid.UUID) (domain.Role, error) {
	const q = `
SELECT id, vault_id, name, capabilities, is_seed
  FROM vault_roles
 WHERE id = $1`
	return s.scanOne(ctx, q, roleID)
}

func (s *RoleStore) GetByName(ctx context.Context, vaultID uuid.UUID, name string) (domain.Role, error) {
	const q = `
SELECT id, vault_id, name, capabilities, is_seed
  FROM vault_roles
 WHERE vault_id = $1 AND name = $2`
	return s.scanOne(ctx, q, vaultID, name)
}

func (s *RoleStore) ListForVault(ctx context.Context, vaultID uuid.UUID) ([]domain.Role, error) {
	const q = `
SELECT id, vault_id, name, capabilities, is_seed
  FROM vault_roles
 WHERE vault_id = $1
 ORDER BY is_seed DESC, name ASC`
	rows, err := s.pool.Query(ctx, q, vaultID)
	if err != nil {
		return nil, fmt.Errorf("role store: list: %w", errMap(err))
	}
	defer rows.Close()

	var out []domain.Role
	for rows.Next() {
		r, err := scanRole(rows)
		if err != nil {
			return nil, fmt.Errorf("role store: list scan: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("role store: list rows: %w", err)
	}
	return out, nil
}

func (s *RoleStore) Update(ctx context.Context, r domain.Role) error {
	return runTx(ctx, s.pool, func(tx pgx.Tx) error {
		var isSeed bool
		err := tx.QueryRow(ctx,
			`SELECT is_seed FROM vault_roles WHERE vault_id = $1 AND id = $2`,
			r.VaultID, r.ID,
		).Scan(&isSeed)
		if err != nil {
			if errors.Is(errMap(err), domain.ErrNotFound) {
				return fmt.Errorf("role store: update: %w", domain.ErrNotFound)
			}
			return fmt.Errorf("role store: update: probe: %w", errMap(err))
		}
		if isSeed {
			return fmt.Errorf("role store: update: %w", domain.ErrSeedRoleProtected)
		}
		caps, err := marshalCaps(r.Capabilities)
		if err != nil {
			return fmt.Errorf("role store: update: marshal caps: %w", err)
		}
		const q = `
UPDATE vault_roles
   SET name = $3, capabilities = $4::jsonb
 WHERE vault_id = $1 AND id = $2`
		if _, err := tx.Exec(ctx, q, r.VaultID, r.ID, r.Name, caps); err != nil {
			return fmt.Errorf("role store: update: %w", errMap(err))
		}
		return nil
	})
}

func (s *RoleStore) Delete(ctx context.Context, vaultID, roleID uuid.UUID) error {
	return runTx(ctx, s.pool, func(tx pgx.Tx) error {
		var isSeed bool
		err := tx.QueryRow(ctx,
			`SELECT is_seed FROM vault_roles WHERE vault_id = $1 AND id = $2`,
			vaultID, roleID,
		).Scan(&isSeed)
		if err != nil {
			if errors.Is(errMap(err), domain.ErrNotFound) {
				return fmt.Errorf("role store: delete: %w", domain.ErrNotFound)
			}
			return fmt.Errorf("role store: delete: probe: %w", errMap(err))
		}
		if isSeed {
			return fmt.Errorf("role store: delete: %w", domain.ErrSeedRoleProtected)
		}
		const q = `DELETE FROM vault_roles WHERE vault_id = $1 AND id = $2`
		tag, err := tx.Exec(ctx, q, vaultID, roleID)
		if err != nil {
			return fmt.Errorf("role store: delete: %w", errMap(err))
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("role store: delete: %w", domain.ErrNotFound)
		}
		return nil
	})
}

// SeedForVault inserts the canonical seed roles. Returns the slice in
// canonical order (Admin, Editor, Viewer, Commenter).
func (s *RoleStore) SeedForVault(ctx context.Context, vaultID uuid.UUID) ([]domain.Role, error) {
	seedNames := []string{"Admin", "Editor", "Viewer", "Commenter"}
	seedCaps := domain.SeedRoles()

	type seed struct {
		id   uuid.UUID
		name string
		caps domain.CapabilitySet
		raw  []byte
	}
	prepared := make([]seed, 0, len(seedNames))
	for _, name := range seedNames {
		caps, ok := seedCaps[name]
		if !ok {
			continue
		}
		marshalled, err := marshalCaps(caps)
		if err != nil {
			return nil, fmt.Errorf("role store: seed: marshal %q: %w", name, err)
		}
		prepared = append(prepared, seed{
			id:   uuid.New(),
			name: name,
			caps: caps,
			raw:  marshalled,
		})
	}

	out := make([]domain.Role, 0, len(prepared))
	err := runTx(ctx, s.pool, func(tx pgx.Tx) error {
		const q = `
INSERT INTO vault_roles (id, vault_id, name, capabilities, is_seed)
VALUES ($1, $2, $3, $4::jsonb, TRUE)`
		for _, sd := range prepared {
			if _, err := tx.Exec(ctx, q, sd.id, vaultID, sd.name, sd.raw); err != nil {
				return fmt.Errorf("role store: seed %q: %w", sd.name, errMap(err))
			}
			out = append(out, domain.Role{
				ID:           sd.id,
				VaultID:      vaultID,
				Name:         sd.name,
				Capabilities: sd.caps,
				IsSeed:       true,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// CountMembersWithRole returns how many vault_members rows reference roleID.
func (s *RoleStore) CountMembersWithRole(ctx context.Context, roleID uuid.UUID) (int, error) {
	const q = `SELECT COUNT(*) FROM vault_members WHERE role_id = $1`
	var n int
	if err := s.pool.QueryRow(ctx, q, roleID).Scan(&n); err != nil {
		return 0, fmt.Errorf("role store: count members: %w", errMap(err))
	}
	return n, nil
}

// MembersWithRole returns the user ids holding roleID.
func (s *RoleStore) MembersWithRole(ctx context.Context, roleID uuid.UUID) ([]uuid.UUID, error) {
	const q = `SELECT user_id FROM vault_members WHERE role_id = $1`
	rows, err := s.pool.Query(ctx, q, roleID)
	if err != nil {
		return nil, fmt.Errorf("role store: members with role: %w", errMap(err))
	}
	defer rows.Close()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("role store: members with role scan: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func marshalCaps(cs domain.CapabilitySet) ([]byte, error) {
	if cs == nil {
		cs = domain.CapabilitySet{}
	}
	return json.Marshal(cs)
}

func unmarshalCaps(b []byte) (domain.CapabilitySet, error) {
	var cs domain.CapabilitySet
	if len(b) == 0 {
		return cs, nil
	}
	if err := json.Unmarshal(b, &cs); err != nil {
		return nil, err
	}
	return cs, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanRole(r rowScanner) (domain.Role, error) {
	var (
		role domain.Role
		caps []byte
	)
	if err := r.Scan(&role.ID, &role.VaultID, &role.Name, &caps, &role.IsSeed); err != nil {
		return domain.Role{}, err
	}
	cs, err := unmarshalCaps(caps)
	if err != nil {
		return domain.Role{}, fmt.Errorf("decode capabilities: %w", err)
	}
	role.Capabilities = cs
	return role, nil
}

func (s *RoleStore) scanOne(ctx context.Context, q string, args ...any) (domain.Role, error) {
	row := s.pool.QueryRow(ctx, q, args...)
	r, err := scanRole(row)
	if err != nil {
		if errors.Is(errMap(err), domain.ErrNotFound) {
			return domain.Role{}, fmt.Errorf("role store: %w", domain.ErrNotFound)
		}
		return domain.Role{}, fmt.Errorf("role store: get: %w", errMap(err))
	}
	return r, nil
}
