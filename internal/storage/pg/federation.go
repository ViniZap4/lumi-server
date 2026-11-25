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

const federationCols = `id, vault_id, role, peer_url, peer_pubkey, jurisdiction, status, last_acked_seq, created_at, revoked_at,
  mode, sever_policy, mirror_acked_seq, home_seq, last_contact_at, paused_at, resync_requested_at, promoted_at,
  last_integrity_at, publish`

func (s *FederationStore) Insert(ctx context.Context, f domain.Federation) (domain.Federation, error) {
	const q = `
INSERT INTO vault_federations (id, vault_id, role, peer_url, peer_pubkey, jurisdiction, status, created_at, mode, sever_policy, publish)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`
	if f.ID == uuid.Nil {
		f.ID = uuid.New()
	}
	if f.CreatedAt.IsZero() {
		f.CreatedAt = time.Now().UTC()
	}
	if f.Mode == "" {
		f.Mode = "replica"
	}
	if f.SeverPolicy == "" {
		f.SeverPolicy = "keep"
	}
	_, err := s.pool.Exec(ctx, q, f.ID, f.VaultID, f.Role, f.PeerURL, f.PeerPubKey, f.Jurisdiction, f.Status, f.CreatedAt, f.Mode, f.SeverPolicy, jsonbOrNil(f.Publish))
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
	if err := scan(&f.ID, &f.VaultID, &f.Role, &f.PeerURL, &f.PeerPubKey, &f.Jurisdiction, &f.Status, &f.LastAckedSeq, &f.CreatedAt, &f.RevokedAt,
		&f.Mode, &f.SeverPolicy, &f.MirrorAckedSeq, &f.HomeSeq, &f.LastContactAt, &f.PausedAt, &f.ResyncRequestedAt, &f.PromotedAt,
		&f.LastIntegrityAt, &f.Publish); err != nil {
		return domain.Federation{}, err
	}
	return f, nil
}

// ---- mirrors (docs/SPEC-ESPELHO-SELADO.md part A) ------------------------------

// RecordMirrorAck stores a mirror's acknowledged home seq (monotonic) and
// stamps last contact (home side).
func (s *FederationStore) RecordMirrorAck(ctx context.Context, vaultID uuid.UUID, peerURL string, seq int64) error {
	_, err := s.pool.Exec(ctx, `
UPDATE vault_federations
   SET mirror_acked_seq = GREATEST(mirror_acked_seq, $3), last_contact_at = NOW()
 WHERE vault_id = $1 AND peer_url = $2 AND role = 'home'`, vaultID, peerURL, seq)
	if err != nil {
		return fmt.Errorf("federation store: mirror ack: %w", errMap(err))
	}
	return nil
}

// RecordHomeSeq stores the home seq a mirror fully applied (mirror side).
func (s *FederationStore) RecordHomeSeq(ctx context.Context, vaultID uuid.UUID, peerURL string, seq int64) error {
	_, err := s.pool.Exec(ctx, `
UPDATE vault_federations
   SET home_seq = $3, last_contact_at = NOW()
 WHERE vault_id = $1 AND peer_url = $2 AND role = 'follower'`, vaultID, peerURL, seq)
	if err != nil {
		return fmt.Errorf("federation store: home seq: %w", errMap(err))
	}
	return nil
}

// TouchContact stamps last_contact_at of a link.
func (s *FederationStore) TouchContact(ctx context.Context, vaultID uuid.UUID, peerURL string) error {
	_, err := s.pool.Exec(ctx, `UPDATE vault_federations SET last_contact_at = NOW() WHERE vault_id = $1 AND peer_url = $2`, vaultID, peerURL)
	if err != nil {
		return fmt.Errorf("federation store: touch contact: %w", errMap(err))
	}
	return nil
}

// PendingDeletes counts the vault's tombstones a mirror has not
// acknowledged (seq > afterSeq) and returns the oldest one's time.
func (s *FederationStore) PendingDeletes(ctx context.Context, vaultID uuid.UUID, afterSeq int64) (int64, *time.Time, error) {
	var n int64
	var oldest *time.Time
	err := s.pool.QueryRow(ctx, `
SELECT count(*), min(deleted_at) FROM note_tombstones WHERE vault_id = $1 AND seq > $2`, vaultID, afterSeq).Scan(&n, &oldest)
	if err != nil {
		return 0, nil, fmt.Errorf("federation store: pending deletes: %w", errMap(err))
	}
	return n, oldest, nil
}

// VaultHead returns this server's seq for the vault (0 without a head row).
func (s *FederationStore) VaultHead(ctx context.Context, vaultID uuid.UUID) (int64, error) {
	var seq int64
	err := s.pool.QueryRow(ctx, `SELECT COALESCE((SELECT seq FROM vault_heads WHERE vault_id = $1), 0)`, vaultID).Scan(&seq)
	if err != nil {
		return 0, fmt.Errorf("federation store: head: %w", errMap(err))
	}
	return seq, nil
}

// SetPaused pauses (or resumes) a link without revoking it.
func (s *FederationStore) SetPaused(ctx context.Context, id uuid.UUID, paused bool) error {
	tag, err := s.pool.Exec(ctx, `
UPDATE vault_federations SET paused_at = CASE WHEN $2 THEN COALESCE(paused_at, NOW()) ELSE NULL END
 WHERE id = $1`, id, paused)
	if err != nil {
		return fmt.Errorf("federation store: set paused: %w", errMap(err))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("federation store: set paused: %w", domain.ErrNotFound)
	}
	return nil
}

// RequestResync forgets a mirror's progress and asks the running server
// to redo a full pass.
func (s *FederationStore) RequestResync(ctx context.Context, id uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `
UPDATE vault_federations SET home_seq = 0, backfill_cursor = NULL, resync_requested_at = NOW()
 WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("federation store: request resync: %w", errMap(err))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("federation store: request resync: %w", domain.ErrNotFound)
	}
	return nil
}

// MarkPromoted severs a mirror's follower row and records the promotion.
func (s *FederationStore) MarkPromoted(ctx context.Context, id uuid.UUID, at time.Time) error {
	tag, err := s.pool.Exec(ctx, `
UPDATE vault_federations
   SET promoted_at = $2,
       status = CASE WHEN status = 'active' THEN 'severed' ELSE status END,
       revoked_at = COALESCE(revoked_at, $2)
 WHERE id = $1 AND role = 'follower' AND mode = 'mirror' AND promoted_at IS NULL`, id, at)
	if err != nil {
		return fmt.Errorf("federation store: mark promoted: %w", errMap(err))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("federation store: mark promoted: %w", domain.ErrNotFound)
	}
	return nil
}

// ListAll lists every link (the manager's reconcile sweep).
func (s *FederationStore) ListAll(ctx context.Context) ([]domain.Federation, error) {
	return s.list(ctx, `SELECT `+federationCols+` FROM vault_federations ORDER BY created_at ASC`)
}

// FederationInviteStore persists federation_invites rows.
type FederationInviteStore struct {
	pool *pgxpool.Pool
}

func NewFederationInviteStore(pool *pgxpool.Pool) *FederationInviteStore {
	return &FederationInviteStore{pool: pool}
}

const fedInviteCols = `token, vault_id, inviter_user_id, server_url_hint, expires_at, created_at, used_at, revoked_at, mode, sever_policy, publish`

func (s *FederationInviteStore) Create(ctx context.Context, inv domain.FederationInvite) error {
	const q = `
INSERT INTO federation_invites (token, vault_id, inviter_user_id, server_url_hint, expires_at, created_at, mode, sever_policy, publish)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`
	if inv.Mode == "" {
		inv.Mode = "replica"
	}
	if inv.SeverPolicy == "" {
		inv.SeverPolicy = "keep"
	}
	_, err := s.pool.Exec(ctx, q, inv.Token, inv.VaultID, inv.InviterUserID, inv.ServerURLHint, inv.ExpiresAt, inv.CreatedAt, inv.Mode, inv.SeverPolicy, jsonbOrNil(inv.Publish))
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
		&inv.ExpiresAt, &inv.CreatedAt, &inv.UsedAt, &inv.RevokedAt, &inv.Mode, &inv.SeverPolicy, &inv.Publish,
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
			&inv.ExpiresAt, &inv.CreatedAt, &inv.UsedAt, &inv.RevokedAt, &inv.Mode, &inv.SeverPolicy, &inv.Publish,
		); err != nil {
			return nil, fmt.Errorf("federation invite store: list scan: %w", err)
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}

// jsonbOrNil passes a JSON document to a JSONB parameter (nil → NULL).
func jsonbOrNil(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return string(b)
}

// RecordIntegrity stamps a mirror link's last completed integrity pass.
func (s *FederationStore) RecordIntegrity(ctx context.Context, vaultID uuid.UUID, peerURL string, at time.Time) error {
	_, err := s.pool.Exec(ctx, `
UPDATE vault_federations SET last_integrity_at = $3
 WHERE vault_id = $1 AND peer_url = $2 AND role = 'follower'`, vaultID, peerURL, at)
	if err != nil {
		return fmt.Errorf("federation store: integrity: %w", errMap(err))
	}
	return nil
}
