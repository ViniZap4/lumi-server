package auth

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

type recAudit struct {
	mu      sync.Mutex
	entries []domain.AuditEntry
}

func (r *recAudit) Record(_ context.Context, e domain.AuditEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, e)
	return nil
}

func (r *recAudit) last(t *testing.T) (domain.AuditEntry, map[string]any) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.entries) == 0 {
		t.Fatal("no audit entry")
	}
	e := r.entries[len(r.entries)-1]
	var p map[string]any
	_ = json.Unmarshal(e.Payload, &p)
	return e, p
}

func newAdminLoginService(t *testing.T) (*Service, *memRepo, *recAudit, *domain.User) {
	t.Helper()
	svc, repo, _, u := newLockoutService(t)
	audit := &recAudit{}
	svc.audit = audit
	repo.users[u.ID].ServerAdmin = true
	return svc, repo, audit, u
}

func TestAdminLogin_SuccessAndGenericRefusals(t *testing.T) {
	svc, repo, audit, u := newAdminLoginService(t)
	ctx := context.Background()
	good := LoginInput{Username: "Alice", Password: "correct horse 9", IP: "198.51.100.7", UserAgent: "ua"}

	got, err := svc.AdminLogin(ctx, good)
	if err != nil || got.ID != u.ID {
		t.Fatalf("admin login: %+v %v", got, err)
	}
	if len(audit.entries) != 0 {
		t.Fatalf("success must not write auth.* rows (the admin service audits admin.session.create): %+v", audit.entries)
	}

	// Every refusal is the same error, audited as admin.login_failed with
	// the reason and a masked username.
	cases := []struct {
		name   string
		in     LoginInput
		setup  func()
		reason string
	}{
		{"unknown user", LoginInput{Username: "nobody", Password: "x", IP: "198.51.100.7"}, nil, "invalid_credentials"},
		{"bad username", LoginInput{Username: "!", Password: "x", IP: "198.51.100.7"}, nil, "invalid_username"},
		{"wrong password", LoginInput{Username: "alice", Password: "nope nope 1", IP: "198.51.100.7"}, nil, "invalid_credentials"},
		{"not a server admin", good, func() { repo.users[u.ID].ServerAdmin = false }, "not_server_admin"},
		{"disabled", good, func() {
			now := time.Now()
			repo.users[u.ID].ServerAdmin, repo.users[u.ID].DisabledAt = true, &now
		}, "account_disabled"},
	}
	for _, c := range cases {
		if c.setup != nil {
			c.setup()
		}
		if _, err := svc.AdminLogin(ctx, c.in); !errors.Is(err, domain.ErrInvalidCredentials) {
			t.Fatalf("%s: got %v", c.name, err)
		}
		e, p := audit.last(t)
		if e.Action != domain.ActionAdminLoginFailed || p["reason"] != c.reason {
			t.Fatalf("%s: audit %s %v", c.name, e.Action, p)
		}
		if p["username"] == c.in.Username && len(c.in.Username) > 2 {
			t.Fatalf("%s: username not masked: %v", c.name, p)
		}
	}
	// The wrong password counted toward the lockout; the non-admin with
	// the right password did not.
	if repo.fails != 1 {
		t.Fatalf("lockout count = %d, want 1", repo.fails)
	}
}

func TestAdminLogin_LockoutShared(t *testing.T) {
	svc, repo, audit, u := newAdminLoginService(t)
	ctx := context.Background()
	for i := 0; i < LockoutThreshold; i++ {
		_, _ = svc.AdminLogin(ctx, LoginInput{Username: "alice", Password: "wrong pass 1"})
	}
	if repo.users[u.ID].LockedUntil == nil {
		t.Fatal("not locked after the threshold")
	}
	good := LoginInput{Username: "alice", Password: "correct horse 9"}
	if _, err := svc.AdminLogin(ctx, good); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("locked admin login: %v", err)
	}
	if e, p := audit.last(t); e.Action != domain.ActionAdminLoginFailed || p["reason"] != "account_locked" {
		t.Fatalf("audit %s %v", e.Action, p)
	}
	// The lock is the account's, not the route's: the public login is
	// refused too.
	if _, err := svc.Login(ctx, good); !errors.Is(err, domain.ErrInvalidCredentials) {
		t.Fatalf("public login while locked: %v", err)
	}
}

func TestAdminLogin_RateLimits(t *testing.T) {
	svc, _, audit, _ := newAdminLoginService(t)
	ctx := context.Background()
	svc.rlUser = NewRateLimiter(2, time.Minute, time.Hour)
	for i := 0; i < 2; i++ {
		_, _ = svc.AdminLogin(ctx, LoginInput{Username: "alice", Password: "wrong pass 1", IP: "198.51.100.1"})
	}
	if _, err := svc.AdminLogin(ctx, LoginInput{Username: "alice", Password: "correct horse 9", IP: "198.51.100.2"}); !errors.Is(err, domain.ErrRateLimited) {
		t.Fatalf("per-user limit: %v", err)
	}
	if e, p := audit.last(t); e.Action != domain.ActionAdminLoginFailed || p["reason"] != "rate_limited_user" {
		t.Fatalf("audit %s %v", e.Action, p)
	}

	svc.rlUser = NewRateLimiter(1000, time.Minute, time.Hour)
	svc.rlIP = NewRateLimiter(1, time.Minute, time.Hour)
	_, _ = svc.AdminLogin(ctx, LoginInput{Username: "bob", Password: "x", IP: "203.0.113.9"})
	if _, err := svc.AdminLogin(ctx, LoginInput{Username: "alice", Password: "correct horse 9", IP: "203.0.113.9"}); !errors.Is(err, domain.ErrRateLimited) {
		t.Fatalf("per-ip limit: %v", err)
	}
}

// granterRepo is a UserCounter + ServerAdminGranter over memRepo.
type granterRepo struct {
	*memRepo
	granted []domain.AuditEntry
}

func (g *granterRepo) CountUsers(context.Context) (int, error) { return len(g.users), nil }
func (g *granterRepo) CountServerAdmins(context.Context) (int, error) {
	n := 0
	for _, u := range g.users {
		if u.ServerAdmin {
			n++
		}
	}
	return n, nil
}
func (g *granterRepo) GrantServerAdmin(_ context.Context, id uuid.UUID, e domain.AuditEntry) error {
	g.users[id].ServerAdmin = true
	g.granted = append(g.granted, e)
	return nil
}

func TestBootstrap_AdoptsExistingAdminOnlyWithMatchingPassword(t *testing.T) {
	ctx := context.Background()
	hash, _ := bcrypt.GenerateFromPassword([]byte("correct horse 9"), bcrypt.MinCost)
	u := &domain.User{ID: uuid.New(), Username: "root", PasswordHash: string(hash)}
	repo := &granterRepo{memRepo: &memRepo{users: map[uuid.UUID]*domain.User{u.ID: u}}}
	svc, err := NewService(repo.memRepo, &memSessions{m: map[string]domain.Session{}}, nopConsents{}, nopAudit{}, Config{Logger: zerolog.Nop()})
	if err != nil {
		t.Fatal(err)
	}

	// Wrong password in the env: nothing granted.
	if err := Bootstrap(ctx, svc, repo, BootstrapConfig{Username: "root", Password: "something else 1"}); err != nil {
		t.Fatal(err)
	}
	if u.ServerAdmin {
		t.Fatal("granted with a password that does not match")
	}
	// Matching password, no server admin yet: granted and audited.
	if err := Bootstrap(ctx, svc, repo, BootstrapConfig{Username: "root", Password: "correct horse 9"}); err != nil {
		t.Fatal(err)
	}
	if !u.ServerAdmin || len(repo.granted) != 1 || repo.granted[0].Action != "admin.user.server_admin" {
		t.Fatalf("server_admin=%v granted=%+v", u.ServerAdmin, repo.granted)
	}
	// Once one exists, the env never grants again.
	v := &domain.User{ID: uuid.New(), Username: "other", PasswordHash: string(hash)}
	repo.users[v.ID] = v
	_ = Bootstrap(ctx, svc, repo, BootstrapConfig{Username: "other", Password: "correct horse 9"})
	if v.ServerAdmin {
		t.Fatal("granted while a server admin exists")
	}
}
