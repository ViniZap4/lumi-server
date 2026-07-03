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

// ServerKeyStore persists the single Ed25519 keypair (v3 F1).
type ServerKeyStore struct {
	pool *pgxpool.Pool
}

func NewServerKeyStore(pool *pgxpool.Pool) *ServerKeyStore {
	return &ServerKeyStore{pool: pool}
}

// Get returns the stored keypair, or domain.ErrNotFound before first boot.
func (s *ServerKeyStore) Get(ctx context.Context) (pub, priv []byte, err error) {
	const q = `SELECT public_key, private_key FROM server_keys WHERE id = 1`
	if err := s.pool.QueryRow(ctx, q).Scan(&pub, &priv); err != nil {
		return nil, nil, fmt.Errorf("server key store: get: %w", errMap(err))
	}
	return pub, priv, nil
}

// Insert stores the keypair. The id=1 constraint makes concurrent first
// boots race safely: exactly one insert wins, losers re-Get.
func (s *ServerKeyStore) Insert(ctx context.Context, pub, priv []byte) error {
	const q = `
INSERT INTO server_keys (id, public_key, private_key)
VALUES (1, $1, $2)
ON CONFLICT (id) DO NOTHING`
	if _, err := s.pool.Exec(ctx, q, pub, priv); err != nil {
		return fmt.Errorf("server key store: insert: %w", errMap(err))
	}
	return nil
}

// FederationStore persists vault_federations rows.
type FederationStore struct {
	pool *pgxpool.Pool
}

func NewFederationStore(pool *pgxpool.Pool) *FederationStore {
	return &FederationStore{pool: pool}
}

const federationCols = `id, vault_id, role, peer_url, peer_pubkey, jurisdiction, status, last_acked_seq, created_at, revoked_at`

func (s *FederationStore) Insert(ctx context.Context, f domain.Federation) (domain.Federation, error) {
	const q = `
INSERT INTO vault_federations (id, vault_id, role, peer_url, peer_pubkey, jurisdiction, status, created_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	if f.ID == uuid.Nil {
		f.ID = uuid.New()
	}
	if f.CreatedAt.IsZero() {
		f.CreatedAt = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, q, f.ID, f.VaultID, f.Role, f.PeerURL, f.PeerPubKey, f.Jurisdiction, f.Status, f.CreatedAt)
	if err != nil {
		return domain.Federation{}, fmt.Errorf("federation store: insert: %w", errMap(err))
	}
	return f, nil
}

func (s *FederationStore) Get(ctx context.Context, id uuid.UUID) (domain.Federation, error) {
	q := `SELECT ` + federationCols + ` FROM vault_federations WHERE id = $1`
	row := s.pool.QueryRow(ctx, q, id)
	f, err := scanFederation(row.Scan)
	if err != nil {
		if errors.Is(errMap(err), domain.ErrNotFound) {
			return domain.Federation{}, fmt.Errorf("federation store: %w", domain.ErrNotFound)
		}
		return domain.Federation{}, fmt.Errorf("federation store: get: %w", errMap(err))
	}
	return f, nil
}

func (s *FederationStore) ListForVault(ctx context.Context, vaultID uuid.UUID) ([]domain.Federation, error) {
	q := `SELECT ` + federationCols + ` FROM vault_federations WHERE vault_id = $1 ORDER BY created_at ASC`
	return s.list(ctx, q, vaultID)
}

// ListActiveByRole feeds the relay manager's boot sweep ('follower') and
// any future home-side bookkeeping.
func (s *FederationStore) ListActiveByRole(ctx context.Context, role string) ([]domain.Federation, error) {
	q := `SELECT ` + federationCols + ` FROM vault_federations WHERE role = $1 AND status = 'active' ORDER BY created_at ASC`
	return s.list(ctx, q, role)
}

// GetActiveByVaultAndPeer authenticates relay challenges/upgrades.
func (s *FederationStore) GetActiveByVaultAndPeer(ctx context.Context, vaultID uuid.UUID, peerURL string) (domain.Federation, error) {
	q := `SELECT ` + federationCols + ` FROM vault_federations WHERE vault_id = $1 AND peer_url = $2 AND status = 'active'`
	row := s.pool.QueryRow(ctx, q, vaultID, peerURL)
	f, err := scanFederation(row.Scan)
	if err != nil {
		if errors.Is(errMap(err), domain.ErrNotFound) {
			return domain.Federation{}, fmt.Errorf("federation store: %w", domain.ErrNotFound)
		}
		return domain.Federation{}, fmt.Errorf("federation store: get by peer: %w", errMap(err))
	}
	return f, nil
}

func (s *FederationStore) list(ctx context.Context, q string, args ...any) ([]domain.Federation, error) {
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("federation store: list: %w", errMap(err))
	}
	defer rows.Close()

	var out []domain.Federation
	for rows.Next() {
		f, err := scanFederation(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("federation store: list scan: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// UpdateStatus moves a federation link to revoked/severed and stamps revoked_at.
func (s *FederationStore) UpdateStatus(ctx context.Context, id uuid.UUID, status string, at time.Time) error {
	const q = `UPDATE vault_federations SET status = $2, revoked_at = $3 WHERE id = $1`
	tag, err := s.pool.Exec(ctx, q, id, status, at)
	if err != nil {
		return fmt.Errorf("federation store: update status: %w", errMap(err))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("federation store: update status: %w", domain.ErrNotFound)
	}
	return nil
}

func scanFederation(scan func(dest ...any) error) (domain.Federation, error) {
	var f domain.Federation
	if err := scan(&f.ID, &f.VaultID, &f.Role, &f.PeerURL, &f.PeerPubKey, &f.Jurisdiction, &f.Status, &f.LastAckedSeq, &f.CreatedAt, &f.RevokedAt); err != nil {
		return domain.Federation{}, err
	}
	return f, nil
}

// FederationInviteStore persists federation_invites rows.
type FederationInviteStore struct {
	pool *pgxpool.Pool
}

func NewFederationInviteStore(pool *pgxpool.Pool) *FederationInviteStore {
	return &FederationInviteStore{pool: pool}
}

const fedInviteCols = `token, vault_id, inviter_user_id, server_url_hint, expires_at, created_at, used_at, revoked_at`

func (s *FederationInviteStore) Create(ctx context.Context, inv domain.FederationInvite) error {
	const q = `
INSERT INTO federation_invites (token, vault_id, inviter_user_id, server_url_hint, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := s.pool.Exec(ctx, q, inv.Token, inv.VaultID, inv.InviterUserID, inv.ServerURLHint, inv.ExpiresAt, inv.CreatedAt)
	if err != nil {
		return fmt.Errorf("federation invite store: create: %w", errMap(err))
	}
	return nil
}

func (s *FederationInviteStore) Get(ctx context.Context, token string) (domain.FederationInvite, error) {
	q := `SELECT ` + fedInviteCols + ` FROM federation_invites WHERE token = $1`
	var inv domain.FederationInvite
	err := s.pool.QueryRow(ctx, q, token).Scan(
		&inv.Token, &inv.VaultID, &inv.InviterUserID, &inv.ServerURLHint,
		&inv.ExpiresAt, &inv.CreatedAt, &inv.UsedAt, &inv.RevokedAt,
	)
	if err != nil {
		if errors.Is(errMap(err), domain.ErrNotFound) {
			return domain.FederationInvite{}, fmt.Errorf("federation invite store: %w", domain.ErrNotFound)
		}
		return domain.FederationInvite{}, fmt.Errorf("federation invite store: get: %w", errMap(err))
	}
	return inv, nil
}

// MarkUsed stamps used_at exactly once: a second concurrent accept loses.
func (s *FederationInviteStore) MarkUsed(ctx context.Context, token string, at time.Time) error {
	const q = `UPDATE federation_invites SET used_at = $2 WHERE token = $1 AND used_at IS NULL`
	tag, err := s.pool.Exec(ctx, q, token, at)
	if err != nil {
		return fmt.Errorf("federation invite store: mark used: %w", errMap(err))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("federation invite store: mark used: %w", domain.ErrConflict)
	}
	return nil
}

func (s *FederationInviteStore) Revoke(ctx context.Context, token string, at time.Time) error {
	const q = `UPDATE federation_invites SET revoked_at = $2 WHERE token = $1 AND revoked_at IS NULL`
	tag, err := s.pool.Exec(ctx, q, token, at)
	if err != nil {
		return fmt.Errorf("federation invite store: revoke: %w", errMap(err))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("federation invite store: revoke: %w", domain.ErrNotFound)
	}
	return nil
}

func (s *FederationInviteStore) ListForVault(ctx context.Context, vaultID uuid.UUID) ([]domain.FederationInvite, error) {
	q := `SELECT ` + fedInviteCols + ` FROM federation_invites WHERE vault_id = $1 ORDER BY created_at DESC`
	rows, err := s.pool.Query(ctx, q, vaultID)
	if err != nil {
		return nil, fmt.Errorf("federation invite store: list: %w", errMap(err))
	}
	defer rows.Close()

	var out []domain.FederationInvite
	for rows.Next() {
		var inv domain.FederationInvite
		if err := rows.Scan(
			&inv.Token, &inv.VaultID, &inv.InviterUserID, &inv.ServerURLHint,
			&inv.ExpiresAt, &inv.CreatedAt, &inv.UsedAt, &inv.RevokedAt,
		); err != nil {
			return nil, fmt.Errorf("federation invite store: list scan: %w", err)
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}
