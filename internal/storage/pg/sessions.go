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

// SessionStore persists bearer tokens.
type SessionStore struct {
	pool *pgxpool.Pool
}

func NewSessionStore(pool *pgxpool.Pool) *SessionStore {
	return &SessionStore{pool: pool}
}

// Create / CreateSession (alias) inserts a new session row.
func (s *SessionStore) Create(ctx context.Context, sess domain.Session) error {
	const q = `
INSERT INTO sessions (token, user_id, created_at, expires_at, last_used_at)
VALUES ($1, $2, $3, $4, $5)`
	_, err := s.pool.Exec(ctx, q,
		sess.Token, sess.UserID, sess.CreatedAt, sess.ExpiresAt, sess.LastUsedAt,
	)
	if err != nil {
		return fmt.Errorf("session store: create: %w", errMap(err))
	}
	return nil
}

// CreateSession is an alias matching internal/auth.SessionStore.
func (s *SessionStore) CreateSession(ctx context.Context, sess domain.Session) error {
	return s.Create(ctx, sess)
}

// Get returns the session for the given token if it has not expired. Side
// effect: bumps last_used_at.
func (s *SessionStore) Get(ctx context.Context, token string) (domain.Session, error) {
	const q = `
UPDATE sessions
   SET last_used_at = NOW()
 WHERE token = $1
   AND expires_at > NOW()
RETURNING token, user_id, created_at, expires_at, last_used_at`

	var out domain.Session
	err := s.pool.QueryRow(ctx, q, token).Scan(
		&out.Token, &out.UserID, &out.CreatedAt, &out.ExpiresAt, &out.LastUsedAt,
	)
	if err != nil {
		if errors.Is(errMap(err), domain.ErrNotFound) {
			var exists bool
			lookupErr := s.pool.QueryRow(ctx,
				`SELECT TRUE FROM sessions WHERE token = $1`, token,
			).Scan(&exists)
			if lookupErr == nil && exists {
				return domain.Session{}, fmt.Errorf("session store: get: %w", domain.ErrTokenExpired)
			}
			return domain.Session{}, fmt.Errorf("session store: get: %w", domain.ErrNotFound)
		}
		return domain.Session{}, fmt.Errorf("session store: get: %w", errMap(err))
	}
	return out, nil
}

// GetSession is the alias matching internal/auth.SessionStore.
// Note: this version does not bump last_used_at; auth's middleware handles
// that explicitly via TouchSession.
func (s *SessionStore) GetSession(ctx context.Context, token string) (domain.Session, error) {
	const q = `
SELECT token, user_id, created_at, expires_at, last_used_at
  FROM sessions
 WHERE token = $1`
	var out domain.Session
	err := s.pool.QueryRow(ctx, q, token).Scan(
		&out.Token, &out.UserID, &out.CreatedAt, &out.ExpiresAt, &out.LastUsedAt,
	)
	if err != nil {
		if errors.Is(errMap(err), domain.ErrNotFound) {
			return domain.Session{}, fmt.Errorf("session store: get: %w", domain.ErrNotFound)
		}
		return domain.Session{}, fmt.Errorf("session store: get: %w", errMap(err))
	}
	return out, nil
}

// TouchSession bumps last_used_at and expires_at for the supplied token.
func (s *SessionStore) TouchSession(ctx context.Context, token string, lastUsedAt, expiresAt time.Time) error {
	const q = `
UPDATE sessions
   SET last_used_at = $2, expires_at = $3
 WHERE token = $1`
	tag, err := s.pool.Exec(ctx, q, token, lastUsedAt, expiresAt)
	if err != nil {
		return fmt.Errorf("session store: touch: %w", errMap(err))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("session store: touch: %w", domain.ErrNotFound)
	}
	return nil
}

func (s *SessionStore) Delete(ctx context.Context, token string) error {
	const q = `DELETE FROM sessions WHERE token = $1`
	tag, err := s.pool.Exec(ctx, q, token)
	if err != nil {
		return fmt.Errorf("session store: delete: %w", errMap(err))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("session store: delete: %w", domain.ErrNotFound)
	}
	return nil
}

// DeleteSession is the alias matching internal/auth.SessionStore. Idempotent.
func (s *SessionStore) DeleteSession(ctx context.Context, token string) error {
	const q = `DELETE FROM sessions WHERE token = $1`
	if _, err := s.pool.Exec(ctx, q, token); err != nil {
		return fmt.Errorf("session store: delete: %w", errMap(err))
	}
	return nil
}

func (s *SessionStore) DeleteAllForUser(ctx context.Context, userID uuid.UUID) error {
	const q = `DELETE FROM sessions WHERE user_id = $1`
	if _, err := s.pool.Exec(ctx, q, userID); err != nil {
		return fmt.Errorf("session store: delete all for user: %w", errMap(err))
	}
	return nil
}

// DeleteSessionsForUser is the alias matching internal/auth.SessionStore.
// Returns count of deleted rows.
func (s *SessionStore) DeleteSessionsForUser(ctx context.Context, userID uuid.UUID) (int, error) {
	const q = `DELETE FROM sessions WHERE user_id = $1`
	tag, err := s.pool.Exec(ctx, q, userID)
	if err != nil {
		return 0, fmt.Errorf("session store: delete for user: %w", errMap(err))
	}
	return int(tag.RowsAffected()), nil
}

// PurgeExpired deletes sessions past their expiry.
func (s *SessionStore) PurgeExpired(ctx context.Context) (int64, error) {
	const q = `DELETE FROM sessions WHERE expires_at <= NOW()`
	tag, err := s.pool.Exec(ctx, q)
	if err != nil {
		return 0, fmt.Errorf("session store: purge: %w", errMap(err))
	}
	return tag.RowsAffected(), nil
}
