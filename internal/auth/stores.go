package auth

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// UserRepo is the slice of user persistence the auth package needs.
type UserRepo interface {
	GetByUsername(ctx context.Context, username string) (domain.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (domain.User, error)
	CreateUser(ctx context.Context, in CreateUserInput) (domain.User, error)
	UpdateDisplayName(ctx context.Context, id uuid.UUID, displayName string) error
	UpdatePasswordHash(ctx context.Context, id uuid.UUID, hash string) error
}

// CreateUserInput is the input shape for new-user creation.
type CreateUserInput struct {
	Username     string
	PasswordHash string
	DisplayName  string
}

// SessionStore manages the sessions table.
type SessionStore interface {
	CreateSession(ctx context.Context, s domain.Session) error
	GetSession(ctx context.Context, token string) (domain.Session, error)
	TouchSession(ctx context.Context, token string, lastUsedAt, expiresAt time.Time) error
	DeleteSession(ctx context.Context, token string) error
	DeleteSessionsForUser(ctx context.Context, userID uuid.UUID) (int, error)
}

// ConsentStore writes immutable consent ledger entries.
type ConsentStore interface {
	RecordConsent(ctx context.Context, c domain.Consent) error
}

// AuditRecorder writes audit_log entries.
type AuditRecorder interface {
	Record(ctx context.Context, e domain.AuditEntry) error
}
