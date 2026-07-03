package pg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// FederatedMemberStore persists cross-server member grants (home side, F3).
type FederatedMemberStore struct {
	pool *pgxpool.Pool
}

func NewFederatedMemberStore(pool *pgxpool.Pool) *FederatedMemberStore {
	return &FederatedMemberStore{pool: pool}
}

// FederatedMemberJoined resolves the role for control-state building and DTOs.
type FederatedMemberJoined struct {
	VaultID   uuid.UUID
	MemberKey string
	RoleID    uuid.UUID
	RoleName  string
	JoinedAt  time.Time
}

func (s *FederatedMemberStore) Add(ctx context.Context, vaultID uuid.UUID, memberKey string, roleID uuid.UUID, addedBy uuid.UUID) error {
	const q = `
INSERT INTO federated_vault_members (vault_id, member_key, role_id, added_by)
VALUES ($1, $2, $3, $4)`
	if _, err := s.pool.Exec(ctx, q, vaultID, memberKey, roleID, addedBy); err != nil {
		return fmt.Errorf("federated member store: add: %w", errMap(err))
	}
	return nil
}

func (s *FederatedMemberStore) ChangeRole(ctx context.Context, vaultID uuid.UUID, memberKey string, roleID uuid.UUID) error {
	const q = `UPDATE federated_vault_members SET role_id = $3 WHERE vault_id = $1 AND member_key = $2`
	tag, err := s.pool.Exec(ctx, q, vaultID, memberKey, roleID)
	if err != nil {
		return fmt.Errorf("federated member store: change role: %w", errMap(err))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("federated member store: change role: %w", domain.ErrNotFound)
	}
	return nil
}

func (s *FederatedMemberStore) Remove(ctx context.Context, vaultID uuid.UUID, memberKey string) error {
	const q = `DELETE FROM federated_vault_members WHERE vault_id = $1 AND member_key = $2`
	tag, err := s.pool.Exec(ctx, q, vaultID, memberKey)
	if err != nil {
		return fmt.Errorf("federated member store: remove: %w", errMap(err))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("federated member store: remove: %w", domain.ErrNotFound)
	}
	return nil
}

func (s *FederatedMemberStore) ListForVault(ctx context.Context, vaultID uuid.UUID) ([]FederatedMemberJoined, error) {
	const q = `
SELECT fm.vault_id, fm.member_key, fm.role_id, vr.name, fm.joined_at
  FROM federated_vault_members fm
  JOIN vault_roles vr ON vr.id = fm.role_id
 WHERE fm.vault_id = $1
 ORDER BY fm.member_key ASC`
	rows, err := s.pool.Query(ctx, q, vaultID)
	if err != nil {
		return nil, fmt.Errorf("federated member store: list: %w", errMap(err))
	}
	defer rows.Close()

	var out []FederatedMemberJoined
	for rows.Next() {
		var m FederatedMemberJoined
		if err := rows.Scan(&m.VaultID, &m.MemberKey, &m.RoleID, &m.RoleName, &m.JoinedAt); err != nil {
			return nil, fmt.Errorf("federated member store: list scan: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ControlStateStore persists home's signed control-state document (F3).
type ControlStateStore struct {
	pool *pgxpool.Pool
}

func NewControlStateStore(pool *pgxpool.Pool) *ControlStateStore {
	return &ControlStateStore{pool: pool}
}

func (s *ControlStateStore) Get(ctx context.Context, vaultID uuid.UUID) (seq int64, state, sig []byte, err error) {
	const q = `SELECT seq, state, signature FROM federation_control_state WHERE vault_id = $1`
	if err := s.pool.QueryRow(ctx, q, vaultID).Scan(&seq, &state, &sig); err != nil {
		return 0, nil, nil, fmt.Errorf("control state store: get: %w", errMap(err))
	}
	return seq, state, sig, nil
}

// Upsert writes the new document iff seq advances — a concurrent rebuild
// with a higher seq wins, matching follower apply semantics.
func (s *ControlStateStore) Upsert(ctx context.Context, vaultID uuid.UUID, seq int64, state, sig []byte) error {
	const q = `
INSERT INTO federation_control_state (vault_id, seq, state, signature, updated_at)
VALUES ($1, $2, $3, $4, NOW())
ON CONFLICT (vault_id) DO UPDATE
   SET seq = EXCLUDED.seq, state = EXCLUDED.state,
       signature = EXCLUDED.signature, updated_at = NOW()
 WHERE federation_control_state.seq < EXCLUDED.seq`
	if _, err := s.pool.Exec(ctx, q, vaultID, seq, state, sig); err != nil {
		return fmt.Errorf("control state store: upsert: %w", errMap(err))
	}
	return nil
}

// ReplicatedControlStore persists the follower-side verified control state.
type ReplicatedControlStore struct {
	pool *pgxpool.Pool
}

func NewReplicatedControlStore(pool *pgxpool.Pool) *ReplicatedControlStore {
	return &ReplicatedControlStore{pool: pool}
}

func (s *ReplicatedControlStore) Get(ctx context.Context, vaultID uuid.UUID) (seq int64, state []byte, err error) {
	const q = `SELECT seq, state FROM replicated_control_state WHERE vault_id = $1`
	if err := s.pool.QueryRow(ctx, q, vaultID).Scan(&seq, &state); err != nil {
		if errors.Is(errMap(err), domain.ErrNotFound) {
			return 0, nil, fmt.Errorf("replicated control store: %w", domain.ErrNotFound)
		}
		return 0, nil, fmt.Errorf("replicated control store: get: %w", errMap(err))
	}
	return seq, state, nil
}

func (s *ReplicatedControlStore) Upsert(ctx context.Context, vaultID uuid.UUID, seq int64, state []byte) error {
	const q = `
INSERT INTO replicated_control_state (vault_id, seq, state, received_at)
VALUES ($1, $2, $3, NOW())
ON CONFLICT (vault_id) DO UPDATE
   SET seq = EXCLUDED.seq, state = EXCLUDED.state, received_at = NOW()
 WHERE replicated_control_state.seq < EXCLUDED.seq`
	if _, err := s.pool.Exec(ctx, q, vaultID, seq, state); err != nil {
		return fmt.Errorf("replicated control store: upsert: %w", errMap(err))
	}
	return nil
}

// UpdateLastAcked records follower replication progress on the federation row.
func (s *FederationStore) UpdateLastAcked(ctx context.Context, vaultID uuid.UUID, peerURL string, seq int64) error {
	const q = `
UPDATE vault_federations SET last_acked_seq = GREATEST(last_acked_seq, $3)
 WHERE vault_id = $1 AND peer_url = $2 AND status = 'active'`
	if _, err := s.pool.Exec(ctx, q, vaultID, peerURL, seq); err != nil {
		return fmt.Errorf("federation store: update acked: %w", errMap(err))
	}
	return nil
}
