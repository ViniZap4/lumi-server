package auth

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// memRepo implements UserRepo and LoginAttempts.
type memRepo struct {
	mu    sync.Mutex
	users map[uuid.UUID]*domain.User
	fails int
	reset int
}

func (r *memRepo) GetByUsername(_ context.Context, name string) (domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, u := range r.users {
		if u.Username == name {
			return *u, nil
		}
	}
	return domain.User{}, domain.ErrNotFound
}

func (r *memRepo) GetByID(_ context.Context, id uuid.UUID) (domain.User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	u, ok := r.users[id]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return *u, nil
}

func (r *memRepo) CreateUser(context.Context, CreateUserInput) (domain.User, error) {
	return domain.User{}, errors.New("unused")
}
func (r *memRepo) UpdateDisplayName(context.Context, uuid.UUID, string) error  { return nil }
func (r *memRepo) UpdatePasswordHash(context.Context, uuid.UUID, string) error { return nil }

func (r *memRepo) RecordLoginFailure(_ context.Context, id uuid.UUID, threshold int, _ time.Duration) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fails++
	u := r.users[id]
	u.FailedLogins++
	if u.FailedLogins >= threshold {
		t := time.Now().Add(time.Minute)
		u.LockedUntil = &t
	}
	return nil
}

func (r *memRepo) ResetLoginFailures(_ context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reset++
	r.users[id].FailedLogins, r.users[id].LockedUntil = 0, nil
	return nil
}

type memSessions struct {
	mu sync.Mutex
	m  map[string]domain.Session
}

func (s *memSessions) CreateSession(_ context.Context, x domain.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[x.Token] = x
	return nil
}
func (s *memSessions) GetSession(_ context.Context, t string) (domain.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.m[t]
	if !ok {
		return domain.Session{}, domain.ErrNotFound
	}
	return x, nil
}
func (s *memSessions) TouchSession(context.Context, string, time.Time, time.Time) error { return nil }
func (s *memSessions) DeleteSession(_ context.Context, t string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, t)
	return nil
}
func (s *memSessions) DeleteSessionsForUser(context.Context, uuid.UUID) (int, error) { return 0, nil }

type nopConsents struct{}

func (nopConsents) RecordConsent(context.Context, domain.Consent) error { return nil }

type nopAudit struct{}

func (nopAudit) Record(context.Context, domain.AuditEntry) error { return nil }

func newLockoutService(t *testing.T) (*Service, *memRepo, *memSessions, *domain.User) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("correct horse 9"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	u := &domain.User{ID: uuid.New(), Username: "alice", PasswordHash: string(hash)}
	repo := &memRepo{users: map[uuid.UUID]*domain.User{u.ID: u}}
	sess := &memSessions{m: map[string]domain.Session{}}
	svc, err := NewService(repo, sess, nopConsents{}, nopAudit{}, Config{Logger: zerolog.Nop()})
	if err != nil {
		t.Fatal(err)
	}
	// Generous in-memory limiters: this test is about the persistent lockout.
	svc.rlUser = NewRateLimiter(1000, time.Minute, time.Hour)
	svc.rlIP = NewRateLimiter(1000, time.Minute, time.Hour)
	return svc, repo, sess, u
}

func TestLoginRefusesDisabledAndLocked(t *testing.T) {
	svc, repo, sess, u := newLockoutService(t)
	ctx := context.Background()
	good := LoginInput{Username: "alice", Password: "correct horse 9", IP: "198.51.100.1"}

	s, err := svc.Login(ctx, good)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	repo.users[u.ID].DisabledAt = &now
	if _, err := svc.Login(ctx, good); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("disabled login: %v", err)
	}
	// An existing session of a disabled account stops working.
	if _, _, err := svc.Validate(ctx, s.Token); !errors.Is(err, domain.ErrTokenInvalid) {
		t.Fatalf("disabled validate: %v", err)
	}
	if _, ok := sess.m[s.Token]; ok {
		t.Fatal("disabled session kept")
	}
	if r, _ := svc.Check(ctx, s.Token); r != "revoked" {
		t.Fatalf("check: %q", r)
	}
	repo.users[u.ID].DisabledAt = nil

	// Wrong passwords count and lock after the threshold; the lock then
	// refuses even the right password, with the same error.
	for i := 0; i < LockoutThreshold; i++ {
		if _, err := svc.Login(ctx, LoginInput{Username: "alice", Password: "wrong pass 1"}); !errors.Is(err, domain.ErrInvalidCredentials) {
			t.Fatal(err)
		}
	}
	if repo.fails != LockoutThreshold || repo.users[u.ID].LockedUntil == nil {
		t.Fatalf("fails=%d locked=%v", repo.fails, repo.users[u.ID].LockedUntil)
	}
	if _, err := svc.Login(ctx, good); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("locked login: %v", err)
	}
	if repo.fails != LockoutThreshold {
		t.Fatal("attempts during the lock were counted")
	}

	// Unlock (operator) then a successful login resets the counter.
	repo.users[u.ID].LockedUntil = nil
	if _, err := svc.Login(ctx, good); err != nil {
		t.Fatalf("after unlock: %v", err)
	}
	if repo.reset != 1 || repo.users[u.ID].FailedLogins != 0 {
		t.Fatalf("reset=%d failed=%d", repo.reset, repo.users[u.ID].FailedLogins)
	}
}
