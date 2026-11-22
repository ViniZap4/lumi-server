package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ViniZap4/lumi-server/internal/admin"
	"github.com/ViniZap4/lumi-server/internal/domain"
)

// AdminStore is the persistence of the admin surface (docs/ADMIN.md). Every
// mutation writes its audit row in the same transaction.
type AdminStore struct {
	pool *pgxpool.Pool
}

func NewAdminStore(pool *pgxpool.Pool) *AdminStore { return &AdminStore{pool: pool} }

var _ admin.Store = (*AdminStore)(nil)

type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// insertAudit is AuditStore.Record against a pool or a transaction.
func insertAudit(ctx context.Context, db execer, e domain.AuditEntry) error {
	const q = `
INSERT INTO audit_log (user_id, vault_id, action, payload, ip, user_agent, created_at)
VALUES ($1, $2, $3, $4::jsonb, $5::inet, $6, COALESCE($7, NOW()))`
	var payloadArg any
	if len(e.Payload) > 0 {
		payloadArg = string(e.Payload)
	}
	var createdAt any
	if !e.CreatedAt.IsZero() {
		createdAt = e.CreatedAt
	}
	if _, err := db.Exec(ctx, q,
		uuidArg(e.UserID), uuidArg(e.VaultID), e.Action, payloadArg,
		nullableStringPtr(e.IP), nullableStringPtr(e.UserAgent), createdAt,
	); err != nil {
		return fmt.Errorf("audit: %w", errMap(err))
	}
	return nil
}

// withAudit runs fn and the audit insert in one transaction.
func (s *AdminStore) withAudit(ctx context.Context, e domain.AuditEntry, fn func(pgx.Tx) error) error {
	return runTx(ctx, s.pool, func(tx pgx.Tx) error {
		if err := fn(tx); err != nil {
			return err
		}
		return insertAudit(ctx, tx, e)
	})
}

func affected(tag pgconn.CommandTag, what string) error {
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("admin store: %s: %w", what, domain.ErrNotFound)
	}
	return nil
}

// ---- tokens -----------------------------------------------------------------------

const tokenCols = `id, name, created_at, last_used_at, expires_at, revoked_at`

func scanToken(row pgx.Row) (admin.Token, error) {
	var t admin.Token
	err := row.Scan(&t.ID, &t.Name, &t.CreatedAt, &t.LastUsedAt, &t.ExpiresAt, &t.RevokedAt)
	if err != nil {
		return admin.Token{}, fmt.Errorf("admin store: token: %w", errMap(err))
	}
	return t, nil
}

func (s *AdminStore) CreateToken(ctx context.Context, t admin.Token, digest []byte, e domain.AuditEntry) error {
	return s.withAudit(ctx, e, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO admin_tokens (id, name, token_hash, created_at, expires_at)
VALUES ($1, $2, $3, $4, $5)`, t.ID, t.Name, digest, t.CreatedAt, t.ExpiresAt)
		if err != nil {
			return fmt.Errorf("admin store: create token: %w", errMap(err))
		}
		return nil
	})
}

func (s *AdminStore) TokenByDigest(ctx context.Context, digest []byte) (admin.Token, error) {
	return scanToken(s.pool.QueryRow(ctx, `SELECT `+tokenCols+` FROM admin_tokens WHERE token_hash = $1`, digest))
}

func (s *AdminStore) GetToken(ctx context.Context, id uuid.UUID) (admin.Token, error) {
	return scanToken(s.pool.QueryRow(ctx, `SELECT `+tokenCols+` FROM admin_tokens WHERE id = $1`, id))
}

func (s *AdminStore) TouchToken(ctx context.Context, id uuid.UUID, at time.Time) error {
	_, err := s.pool.Exec(ctx, `UPDATE admin_tokens SET last_used_at = $2 WHERE id = $1`, id, at)
	if err != nil {
		return fmt.Errorf("admin store: touch token: %w", errMap(err))
	}
	return nil
}

func (s *AdminStore) ListTokens(ctx context.Context, after *admin.Cursor, limit int) ([]admin.Token, bool, error) {
	at, key, err := uuidCursor(after)
	if err != nil {
		return nil, false, err
	}
	rows, err := s.pool.Query(ctx, `
SELECT `+tokenCols+` FROM admin_tokens
 WHERE ($1::timestamptz IS NULL OR (created_at, id) > ($1, $2::uuid))
 ORDER BY created_at, id
 LIMIT $3`, at, key, limitArg(limit))
	if err != nil {
		return nil, false, fmt.Errorf("admin store: list tokens: %w", errMap(err))
	}
	return collectPage(rows, limit, func(r pgx.Rows) (admin.Token, error) { return scanToken(r) })
}

func (s *AdminStore) RevokeToken(ctx context.Context, id uuid.UUID, at time.Time, e domain.AuditEntry) error {
	return s.withAudit(ctx, e, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE admin_tokens SET revoked_at = COALESCE(revoked_at, $2) WHERE id = $1`, id, at)
		if err != nil {
			return fmt.Errorf("admin store: revoke token: %w", errMap(err))
		}
		return affected(tag, "revoke token")
	})
}

// ---- status -------------------------------------------------------------------------

func (s *AdminStore) Counts(ctx context.Context) (admin.Counts, error) {
	var c admin.Counts
	err := s.pool.QueryRow(ctx, `
SELECT (SELECT count(*) FROM users),
       (SELECT count(*) FROM sessions WHERE expires_at > NOW()),
       (SELECT count(*) FROM vaults),
       (SELECT count(*) FROM notes),
       (SELECT count(*) FROM vault_federations WHERE status = 'active'),
       (SELECT count(*) FROM users WHERE disabled_at IS NOT NULL),
       (SELECT count(*) FROM users WHERE disabled_at IS NULL AND locked_until > NOW()),
       (COALESCE((SELECT sum(octet_length(state)) FROM note_yjs_snapshots), 0)
      + COALESCE((SELECT sum(octet_length(update_blob)) FROM note_yjs_updates), 0))::bigint,
       (SELECT count(*) FROM audit_log WHERE action = 'auth.login' AND created_at > NOW() - interval '24 hours'),
       (SELECT count(*) FROM audit_log WHERE action = 'auth.login_failed' AND created_at > NOW() - interval '24 hours'),
       (SELECT count(*) FROM invites WHERE revoked_at IS NULL AND expires_at > NOW() AND use_count < max_uses)`).
		Scan(&c.Users, &c.Sessions, &c.Vaults, &c.Notes, &c.Federations,
			&c.UsersDisabled, &c.UsersLocked, &c.CRDTBytes, &c.Logins24h, &c.LoginFailures24h, &c.InvitesActive)
	if err != nil {
		return admin.Counts{}, fmt.Errorf("admin store: counts: %w", errMap(err))
	}
	// golang-migrate's bookkeeping table: one row (version, dirty).
	err = s.pool.QueryRow(ctx, `SELECT version, dirty FROM schema_migrations LIMIT 1`).Scan(&c.SchemaVersion, &c.SchemaDirty)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return admin.Counts{}, fmt.Errorf("admin store: schema version: %w", errMap(err))
	}
	return c, nil
}

// Ping is a trivial round trip, timed by the service as the DB latency.
func (s *AdminStore) Ping(ctx context.Context) error {
	var one int
	if err := s.pool.QueryRow(ctx, `SELECT 1`).Scan(&one); err != nil {
		return fmt.Errorf("admin store: ping: %w", errMap(err))
	}
	return nil
}

// likePattern turns a search into a case-insensitive substring pattern
// (used with ILIKE ... ESCAPE '\'); "" stays "" (no filter).
func likePattern(q string) string {
	if q == "" {
		return ""
	}
	return "%" + escapeLike(q) + "%"
}

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// escapeLike neutralises LIKE wildcards (ESCAPE '\').
func escapeLike(s string) string { return likeEscaper.Replace(s) }

// ---- users ----------------------------------------------------------------------------

const adminUserSelect = `
SELECT u.id, u.username, u.display_name, u.created_at, u.disabled_at, u.failed_logins, u.locked_until,
       (SELECT count(*) FROM sessions s WHERE s.user_id = u.id AND s.expires_at > NOW()),
       (SELECT count(*) FROM vaults v WHERE v.owner_user_id = u.id),
       (SELECT count(*) FROM vault_members m WHERE m.user_id = u.id),
       (SELECT max(a.created_at) FROM audit_log a WHERE a.user_id = u.id AND a.action = 'auth.login'),
       (SELECT max(s.last_used_at) FROM sessions s WHERE s.user_id = u.id)
  FROM users u`

func scanAdminUser(row pgx.Row) (admin.User, error) {
	var u admin.User
	err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.CreatedAt, &u.DisabledAt, &u.FailedLogins,
		&u.LockedUntil, &u.Sessions, &u.OwnedVaults, &u.Vaults, &u.LastLoginAt, &u.LastSeenAt)
	if err != nil {
		return admin.User{}, fmt.Errorf("admin store: user: %w", errMap(err))
	}
	return u, nil
}

func (s *AdminStore) ListUsers(ctx context.Context, f admin.UserFilter, after string, limit int) ([]admin.User, bool, error) {
	rows, err := s.pool.Query(ctx, adminUserSelect+`
 WHERE u.username > $1
   AND ($3 = '' OR u.username ILIKE $3 ESCAPE '\' OR u.display_name ILIKE $3 ESCAPE '\')
   AND ($4 = ''
        OR ($4 = 'disabled' AND u.disabled_at IS NOT NULL)
        OR ($4 = 'locked' AND u.disabled_at IS NULL AND u.locked_until > NOW())
        OR ($4 = 'active' AND u.disabled_at IS NULL AND (u.locked_until IS NULL OR u.locked_until <= NOW())))
 ORDER BY u.username
 LIMIT $2`, after, limitArg(limit), likePattern(f.Query), f.State)
	if err != nil {
		return nil, false, fmt.Errorf("admin store: list users: %w", errMap(err))
	}
	return collectPage(rows, limit, func(r pgx.Rows) (admin.User, error) { return scanAdminUser(r) })
}

func (s *AdminStore) GetUser(ctx context.Context, id uuid.UUID) (admin.User, error) {
	return scanAdminUser(s.pool.QueryRow(ctx, adminUserSelect+` WHERE u.id = $1`, id))
}

func (s *AdminStore) GetUserByUsername(ctx context.Context, username string) (admin.User, error) {
	return scanAdminUser(s.pool.QueryRow(ctx, adminUserSelect+` WHERE u.username = $1`, username))
}

func (s *AdminStore) OwnedVaultIDs(ctx context.Context, id uuid.UUID) ([]uuid.UUID, error) {
	rows, err := s.pool.Query(ctx, `SELECT id FROM vaults WHERE owner_user_id = $1 ORDER BY slug`, id)
	if err != nil {
		return nil, fmt.Errorf("admin store: owned vaults: %w", errMap(err))
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return nil, fmt.Errorf("admin store: owned vaults: %w", errMap(err))
	}
	return ids, nil
}

func (s *AdminStore) CreateUser(ctx context.Context, u domain.User, e domain.AuditEntry) error {
	return s.withAudit(ctx, e, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
INSERT INTO users (id, username, password_hash, display_name, created_at)
VALUES ($1, $2, $3, $4, $5)`, u.ID, u.Username, u.PasswordHash, u.DisplayName, u.CreatedAt)
		if err != nil {
			return fmt.Errorf("admin store: create user: %w", errMap(err))
		}
		return nil
	})
}

func (s *AdminStore) SetPassword(ctx context.Context, id uuid.UUID, hash string, e domain.AuditEntry) error {
	return s.withAudit(ctx, e, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
UPDATE users SET password_hash = $2, failed_logins = 0, locked_until = NULL WHERE id = $1`, id, hash)
		if err != nil {
			return fmt.Errorf("admin store: set password: %w", errMap(err))
		}
		if err := affected(tag, "set password"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, id); err != nil {
			return fmt.Errorf("admin store: end sessions: %w", errMap(err))
		}
		return nil
	})
}

func (s *AdminStore) SetDisabled(ctx context.Context, id uuid.UUID, disabled bool, e domain.AuditEntry) error {
	return s.withAudit(ctx, e, func(tx pgx.Tx) error {
		q := `UPDATE users SET disabled_at = NULL WHERE id = $1`
		if disabled {
			q = `UPDATE users SET disabled_at = COALESCE(disabled_at, NOW()) WHERE id = $1`
		}
		tag, err := tx.Exec(ctx, q, id)
		if err != nil {
			return fmt.Errorf("admin store: set disabled: %w", errMap(err))
		}
		if err := affected(tag, "set disabled"); err != nil {
			return err
		}
		if disabled {
			if _, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, id); err != nil {
				return fmt.Errorf("admin store: end sessions: %w", errMap(err))
			}
		}
		return nil
	})
}

func (s *AdminStore) Unlock(ctx context.Context, id uuid.UUID, e domain.AuditEntry) error {
	return s.withAudit(ctx, e, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = $1`, id)
		if err != nil {
			return fmt.Errorf("admin store: unlock: %w", errMap(err))
		}
		return affected(tag, "unlock")
	})
}

// ---- sessions -----------------------------------------------------------------------------

const adminSessionSelect = `
SELECT s.token_hash, s.user_id, u.username, s.created_at, s.last_used_at, s.expires_at
  FROM sessions s
  JOIN users u ON u.id = s.user_id`

func scanAdminSession(row pgx.Row) (admin.Session, error) {
	var x admin.Session
	if err := row.Scan(&x.ID, &x.UserID, &x.Username, &x.CreatedAt, &x.LastUsedAt, &x.ExpiresAt); err != nil {
		return admin.Session{}, fmt.Errorf("admin store: session: %w", errMap(err))
	}
	return x, nil
}

// ListSessions pages sessions newest first.
func (s *AdminStore) ListSessions(ctx context.Context, userID *uuid.UUID, after *admin.Cursor, limit int) ([]admin.Session, bool, error) {
	var at any
	key := ""
	if after != nil {
		at, key = after.Time, after.Key
	}
	rows, err := s.pool.Query(ctx, adminSessionSelect+`
 WHERE ($1::uuid IS NULL OR s.user_id = $1)
   AND ($2::timestamptz IS NULL OR (s.created_at, s.token_hash) < ($2, $3::text))
 ORDER BY s.created_at DESC, s.token_hash DESC
 LIMIT $4`, userID, at, key, limitArg(limit))
	if err != nil {
		return nil, false, fmt.Errorf("admin store: list sessions: %w", errMap(err))
	}
	return collectPage(rows, limit, func(r pgx.Rows) (admin.Session, error) { return scanAdminSession(r) })
}

func (s *AdminStore) GetSession(ctx context.Context, id string) (admin.Session, error) {
	return scanAdminSession(s.pool.QueryRow(ctx, adminSessionSelect+` WHERE s.token_hash = $1`, id))
}

func (s *AdminStore) DeleteSession(ctx context.Context, id string, e domain.AuditEntry) error {
	return s.withAudit(ctx, e, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, id)
		if err != nil {
			return fmt.Errorf("admin store: delete session: %w", errMap(err))
		}
		return affected(tag, "delete session")
	})
}

// EndUserSessions deletes all sessions of the user and writes the audit
// row (built from the count) in the same transaction.
func (s *AdminStore) EndUserSessions(ctx context.Context, userID uuid.UUID, e func(n int) domain.AuditEntry) (int, error) {
	var n int
	err := runTx(ctx, s.pool, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE id = $1)`, userID).Scan(&exists); err != nil {
			return fmt.Errorf("admin store: end sessions: %w", errMap(err))
		}
		if !exists {
			return fmt.Errorf("admin store: end sessions: %w", domain.ErrNotFound)
		}
		tag, err := tx.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID)
		if err != nil {
			return fmt.Errorf("admin store: end sessions: %w", errMap(err))
		}
		n = int(tag.RowsAffected())
		return insertAudit(ctx, tx, e(n))
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// ---- vaults --------------------------------------------------------------------------------

const adminVaultSelect = `
SELECT v.id, v.slug, v.name, v.owner_user_id, COALESCE(o.username, ''),
       (SELECT count(*) FROM vault_members m WHERE m.vault_id = v.id),
       (SELECT count(*) FROM federated_vault_members fm WHERE fm.vault_id = v.id),
       (SELECT count(*) FROM notes n WHERE n.vault_id = v.id),
       (COALESCE((SELECT sum(octet_length(sn.state)) FROM note_yjs_snapshots sn WHERE sn.vault_id = v.id), 0)
      + COALESCE((SELECT sum(octet_length(up.update_blob)) FROM note_yjs_updates up WHERE up.vault_id = v.id), 0))::bigint,
       (SELECT f.role FROM vault_federations f WHERE f.vault_id = v.id AND f.status = 'active' LIMIT 1),
       (SELECT count(*) FROM vault_federations f WHERE f.vault_id = v.id AND f.status = 'active'),
       COALESCE(h.seq, 0), h.updated_at,
       (SELECT count(*) FROM invites i WHERE i.vault_id = v.id AND i.revoked_at IS NULL
           AND i.expires_at > NOW() AND i.use_count < i.max_uses),
       v.created_at
  FROM vaults v
  LEFT JOIN users o ON o.id = v.owner_user_id
  LEFT JOIN vault_heads h ON h.vault_id = v.id`

func scanAdminVault(row pgx.Row) (admin.Vault, error) {
	var v admin.Vault
	err := row.Scan(&v.ID, &v.Slug, &v.Name, &v.OwnerID, &v.OwnerUsername, &v.Members, &v.FederatedMembers,
		&v.Notes, &v.CRDTBytes, &v.FederationRole, &v.ActiveFederations, &v.HeadSeq, &v.LastChangeAt,
		&v.InvitesActive, &v.CreatedAt)
	if err != nil {
		return admin.Vault{}, fmt.Errorf("admin store: vault: %w", errMap(err))
	}
	return v, nil
}

// ListVaults pages vaults by slug; userID keeps those the user owns or
// belongs to.
func (s *AdminStore) ListVaults(ctx context.Context, f admin.VaultFilter, after string, limit int) ([]admin.Vault, bool, error) {
	rows, err := s.pool.Query(ctx, adminVaultSelect+`
 WHERE v.slug > $1
   AND ($2::uuid IS NULL OR v.owner_user_id = $2
        OR EXISTS (SELECT 1 FROM vault_members m WHERE m.vault_id = v.id AND m.user_id = $2))
   AND ($4 = '' OR v.slug ILIKE $4 ESCAPE '\' OR v.name ILIKE $4 ESCAPE '\')
 ORDER BY v.slug
 LIMIT $3`, after, f.UserID, limitArg(limit), likePattern(f.Query))
	if err != nil {
		return nil, false, fmt.Errorf("admin store: list vaults: %w", errMap(err))
	}
	return collectPage(rows, limit, func(r pgx.Rows) (admin.Vault, error) { return scanAdminVault(r) })
}

func (s *AdminStore) GetVault(ctx context.Context, id uuid.UUID) (admin.Vault, error) {
	return scanAdminVault(s.pool.QueryRow(ctx, adminVaultSelect+` WHERE v.id = $1`, id))
}

func (s *AdminStore) GetVaultBySlug(ctx context.Context, slug string) (admin.Vault, error) {
	return scanAdminVault(s.pool.QueryRow(ctx, adminVaultSelect+` WHERE v.slug = $1`, slug))
}

// VaultMembers lists the local members (owner first, then by username)
// and the vault's roles by name with their member counts.
func (s *AdminStore) VaultMembers(ctx context.Context, vaultID uuid.UUID) ([]admin.Member, []admin.Role, error) {
	rows, err := s.pool.Query(ctx, `
SELECT m.user_id, u.username, u.display_name, r.id, r.name, (v.owner_user_id = m.user_id), m.joined_at
  FROM vault_members m
  JOIN users u ON u.id = m.user_id
  JOIN vault_roles r ON r.id = m.role_id
  JOIN vaults v ON v.id = m.vault_id
 WHERE m.vault_id = $1
 ORDER BY (v.owner_user_id = m.user_id) DESC, u.username`, vaultID)
	if err != nil {
		return nil, nil, fmt.Errorf("admin store: vault members: %w", errMap(err))
	}
	members, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (admin.Member, error) {
		var m admin.Member
		err := r.Scan(&m.UserID, &m.Username, &m.DisplayName, &m.RoleID, &m.RoleName, &m.Owner, &m.JoinedAt)
		return m, err
	})
	if err != nil {
		return nil, nil, fmt.Errorf("admin store: vault members: %w", errMap(err))
	}
	rows, err = s.pool.Query(ctx, `
SELECT r.id, r.name, r.is_seed, (SELECT count(*) FROM vault_members m WHERE m.role_id = r.id)
  FROM vault_roles r
 WHERE r.vault_id = $1
 ORDER BY r.name`, vaultID)
	if err != nil {
		return nil, nil, fmt.Errorf("admin store: vault roles: %w", errMap(err))
	}
	roles, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (admin.Role, error) {
		var x admin.Role
		err := r.Scan(&x.ID, &x.Name, &x.Seed, &x.Members)
		return x, err
	})
	if err != nil {
		return nil, nil, fmt.Errorf("admin store: vault roles: %w", errMap(err))
	}
	return members, roles, nil
}

// ---- invites ---------------------------------------------------------------------------------

// The id of an invite is the hex SHA-256 of its token; the token itself
// never leaves the database through the admin surface.
const adminInviteSelect = `
SELECT encode(sha256(convert_to(i.token, 'UTF8')), 'hex'), i.vault_id, v.slug, v.name,
       i.inviter_user_id, COALESCE(u.username, ''), i.role_id, COALESCE(r.name, ''), i.email_hint,
       i.max_uses, i.use_count, i.expires_at, i.created_at, i.revoked_at
  FROM invites i
  JOIN vaults v ON v.id = i.vault_id
  LEFT JOIN users u ON u.id = i.inviter_user_id
  LEFT JOIN vault_roles r ON r.id = i.role_id`

const inviteIDExpr = `encode(sha256(convert_to(i.token, 'UTF8')), 'hex')`

func scanAdminInvite(row pgx.Row) (admin.Invite, error) {
	var x admin.Invite
	err := row.Scan(&x.ID, &x.VaultID, &x.VaultSlug, &x.VaultName, &x.InviterID, &x.InviterUsername,
		&x.RoleID, &x.RoleName, &x.EmailHint, &x.MaxUses, &x.UseCount, &x.ExpiresAt, &x.CreatedAt, &x.RevokedAt)
	if err != nil {
		return admin.Invite{}, fmt.Errorf("admin store: invite: %w", errMap(err))
	}
	return x, nil
}

// ListInvites pages invites newest first by (created_at, id).
func (s *AdminStore) ListInvites(ctx context.Context, f admin.InviteFilter, after *admin.Cursor, limit int) ([]admin.Invite, bool, error) {
	var at any
	key := ""
	if after != nil {
		at, key = after.Time, after.Key
	}
	rows, err := s.pool.Query(ctx, adminInviteSelect+`
 WHERE ($1::uuid IS NULL OR i.vault_id = $1)
   AND (NOT $2::bool OR (i.revoked_at IS NULL AND i.expires_at > NOW() AND i.use_count < i.max_uses))
   AND ($3::timestamptz IS NULL OR (i.created_at, `+inviteIDExpr+`) < ($3, $4::text))
 ORDER BY i.created_at DESC, `+inviteIDExpr+` DESC
 LIMIT $5`, f.VaultID, f.ActiveOnly, at, key, limitArg(limit))
	if err != nil {
		return nil, false, fmt.Errorf("admin store: list invites: %w", errMap(err))
	}
	return collectPage(rows, limit, func(r pgx.Rows) (admin.Invite, error) { return scanAdminInvite(r) })
}

func (s *AdminStore) GetInvite(ctx context.Context, id string) (admin.Invite, error) {
	return scanAdminInvite(s.pool.QueryRow(ctx, adminInviteSelect+` WHERE `+inviteIDExpr+` = $1`, id))
}

func (s *AdminStore) RevokeInvite(ctx context.Context, id string, at time.Time, e domain.AuditEntry) error {
	return s.withAudit(ctx, e, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
UPDATE invites i SET revoked_at = COALESCE(i.revoked_at, $2) WHERE `+inviteIDExpr+` = $1`, id, at)
		if err != nil {
			return fmt.Errorf("admin store: revoke invite: %w", errMap(err))
		}
		return affected(tag, "revoke invite")
	})
}

// ---- federations ----------------------------------------------------------------------------

const adminFederationSelect = `
SELECT f.id, f.vault_id, v.slug, v.name, f.role, f.peer_url, f.jurisdiction, f.status, f.last_acked_seq,
       cs.seq, f.created_at, f.revoked_at
  FROM vault_federations f
  JOIN vaults v ON v.id = f.vault_id
  LEFT JOIN federation_control_state cs ON cs.vault_id = f.vault_id AND f.role = 'home'`

func scanAdminFederation(row pgx.Row) (admin.Federation, error) {
	var f admin.Federation
	err := row.Scan(&f.ID, &f.VaultID, &f.VaultSlug, &f.VaultName, &f.Role, &f.PeerURL, &f.Jurisdiction,
		&f.Status, &f.LastAckedSeq, &f.ControlSeq, &f.CreatedAt, &f.RevokedAt)
	if err != nil {
		return admin.Federation{}, fmt.Errorf("admin store: federation: %w", errMap(err))
	}
	return f, nil
}

func (s *AdminStore) ListFederations(ctx context.Context, vaultID *uuid.UUID, after *admin.Cursor, limit int) ([]admin.Federation, bool, error) {
	at, key, err := uuidCursor(after)
	if err != nil {
		return nil, false, err
	}
	rows, err := s.pool.Query(ctx, adminFederationSelect+`
 WHERE ($1::uuid IS NULL OR f.vault_id = $1)
   AND ($2::timestamptz IS NULL OR (f.created_at, f.id) > ($2, $3::uuid))
 ORDER BY f.created_at, f.id
 LIMIT $4`, vaultID, at, key, limitArg(limit))
	if err != nil {
		return nil, false, fmt.Errorf("admin store: list federations: %w", errMap(err))
	}
	return collectPage(rows, limit, func(r pgx.Rows) (admin.Federation, error) { return scanAdminFederation(r) })
}

func (s *AdminStore) GetFederation(ctx context.Context, id uuid.UUID) (admin.Federation, error) {
	return scanAdminFederation(s.pool.QueryRow(ctx, adminFederationSelect+` WHERE f.id = $1`, id))
}

// ---- audit ------------------------------------------------------------------------------------

func (s *AdminStore) RecordAudit(ctx context.Context, e domain.AuditEntry) error {
	return insertAudit(ctx, s.pool, e)
}

// ListAudit pages the whole audit log newest first by id.
func (s *AdminStore) ListAudit(ctx context.Context, q admin.AuditQuery) ([]domain.AuditEntry, bool, error) {
	const sql = `
SELECT id, user_id, vault_id, action, payload, host(ip), user_agent, created_at
  FROM audit_log
 WHERE ($1::bigint = 0 OR id < $1)
   AND (NOT $2::bool OR action LIKE 'admin.%')
   AND ($3::uuid IS NULL OR user_id = $3)
   AND ($4::uuid IS NULL OR vault_id = $4)
   AND ($6 = '' OR (NOT $7::bool AND action = $6) OR ($7::bool AND action LIKE $8 ESCAPE '\'))
   AND ($9::timestamptz IS NULL OR created_at >= $9)
   AND ($10::timestamptz IS NULL OR created_at < $10)
 ORDER BY id DESC
 LIMIT $5`
	prefix := ""
	if q.ActionPrefix {
		prefix = escapeLike(q.Action) + "%"
	}
	list, err := (&AuditStore{pool: s.pool}).queryEntries(ctx, sql, q.Before, q.AdminOn, q.UserID, q.VaultID,
		limitArg(q.Limit), q.Action, q.ActionPrefix, prefix, q.Since, q.Until)
	if err != nil {
		return nil, false, err
	}
	more := q.Limit > 0 && len(list) > q.Limit
	if more {
		list = list[:q.Limit]
	}
	return list, more, nil
}

// ---- paging helpers -----------------------------------------------------------------------------

// limitArg fetches one extra row to learn whether another page exists;
// limit <= 0 means everything (CLI listings).
func limitArg(limit int) any {
	if limit <= 0 {
		return nil
	}
	return limit + 1
}

func collectPage[T any](rows pgx.Rows, limit int, scan func(pgx.Rows) (T, error)) ([]T, bool, error) {
	defer rows.Close()
	var out []T
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, false, err
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, false, fmt.Errorf("admin store: rows: %w", errMap(err))
	}
	more := limit > 0 && len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, nil
}

func uuidCursor(c *admin.Cursor) (at any, key any, err error) {
	if c == nil {
		return nil, nil, nil
	}
	id, perr := uuid.Parse(c.Key)
	if perr != nil {
		return nil, nil, fmt.Errorf("admin store: cursor: %w", domain.ErrValidation)
	}
	return c.Time, id, nil
}
