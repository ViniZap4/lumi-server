package feed

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/ViniZap4/lumi-server/internal/auth"
	"github.com/ViniZap4/lumi-server/internal/domain"
)

// ---- auth fakes (real auth.Service + middleware over in-memory stores) -------------

type memUsers struct {
	mu sync.Mutex
	m  map[uuid.UUID]domain.User
}

func (u *memUsers) GetByUsername(context.Context, string) (domain.User, error) {
	return domain.User{}, domain.ErrNotFound
}
func (u *memUsers) GetByID(_ context.Context, id uuid.UUID) (domain.User, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if x, ok := u.m[id]; ok {
		return x, nil
	}
	return domain.User{}, domain.ErrNotFound
}
func (u *memUsers) CreateUser(context.Context, auth.CreateUserInput) (domain.User, error) {
	return domain.User{}, domain.ErrValidation
}
func (u *memUsers) UpdateDisplayName(context.Context, uuid.UUID, string) error  { return nil }
func (u *memUsers) UpdatePasswordHash(context.Context, uuid.UUID, string) error { return nil }

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
func (s *memSessions) GetSession(_ context.Context, tok string) (domain.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if x, ok := s.m[tok]; ok {
		return x, nil
	}
	return domain.Session{}, domain.ErrNotFound
}
func (s *memSessions) TouchSession(context.Context, string, time.Time, time.Time) error { return nil }
func (s *memSessions) DeleteSession(_ context.Context, tok string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, tok)
	return nil
}
func (s *memSessions) DeleteSessionsForUser(_ context.Context, id uuid.UUID) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, v := range s.m {
		if v.UserID == id {
			delete(s.m, k)
			n++
		}
	}
	return n, nil
}

type nopConsents struct{}

func (nopConsents) RecordConsent(context.Context, domain.Consent) error { return nil }

type nopAudit struct{}

func (nopAudit) Record(context.Context, domain.AuditEntry) error { return nil }

var (
	authOnce sync.Once
	authSvc  *auth.Service
	users    = &memUsers{m: map[uuid.UUID]domain.User{}}
	sessions = &memSessions{m: map[string]domain.Session{}}
)

func testAuth(t *testing.T) *auth.Service {
	t.Helper()
	authOnce.Do(func() {
		var err error
		authSvc, err = auth.NewService(users, sessions, nopConsents{}, nopAudit{}, auth.Config{Logger: zerolog.Nop()})
		if err != nil {
			panic(err)
		}
	})
	return authSvc
}

// account creates a user with one live session and returns (id, token).
func account(t *testing.T) (uuid.UUID, string) {
	t.Helper()
	id := uuid.New()
	tok := "tok-" + uuid.NewString()
	users.mu.Lock()
	users.m[id] = domain.User{ID: id, Username: "u" + id.String()[:8]}
	users.mu.Unlock()
	_ = sessions.CreateSession(context.Background(), domain.Session{
		Token: tok, UserID: id, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	})
	return id, tok
}

// startFeedServer mounts the handler exactly like main.go: authed /api
// group with auth.Required, real listener.
func startFeedServer(t *testing.T, br *Broker) string {
	t.Helper()
	app := fiber.New(fiber.Config{DisableStartupMessage: true, WriteTimeout: 2 * time.Second})
	NewHandler(br).Register(app.Group("/api", auth.Required(testAuth(t))))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = app.Listener(ln) }()
	t.Cleanup(func() { br.Close(); _ = app.Shutdown() })
	return "http://" + ln.Addr().String()
}

type sseClient struct {
	resp   *http.Response
	events chan [2]string // name, data
}

func dial(t *testing.T, url string, header map[string]string) (*http.Response, *sseClient) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusOK {
		return resp, nil
	}
	c := &sseClient{resp: resp, events: make(chan [2]string, 64)}
	go func() {
		defer close(c.events)
		sc := bufio.NewScanner(resp.Body)
		var name string
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				name = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "data: "):
				c.events <- [2]string{name, strings.TrimPrefix(line, "data: ")}
			case line == ": ping":
				c.events <- [2]string{"ping", ""}
			}
		}
	}()
	return resp, c
}

func (c *sseClient) next(t *testing.T) [2]string {
	t.Helper()
	for {
		select {
		case ev, ok := <-c.events:
			if !ok {
				t.Fatal("stream closed")
			}
			if ev[0] == "ping" {
				continue
			}
			return ev
		case <-time.After(2 * time.Second):
			t.Fatal("no event")
		}
	}
}

func (c *sseClient) closed(t *testing.T) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-c.events:
			if !ok {
				return
			}
		case <-deadline:
			t.Fatal("stream not closed")
		}
	}
}

func bearer(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }

// Over the wire: headers, hello, isolation between two accounts, and that
// the stream keeps flowing past the server WriteTimeout (2 s here).
func TestHTTP_StreamIsolationAndHeaders(t *testing.T) {
	dir := newMemDir()
	cfg := testConfig()
	cfg.Ping = 300 * time.Millisecond
	cfg.WriteGrace = time.Second
	br := NewBroker(cfg, dir, nil, zerolog.Nop())
	base := startFeedServer(t, br)
	a, ta := account(t)
	b, tb := account(t)
	va, vb := uuid.New(), uuid.New()
	dir.grant(a, va, "Admin", true)
	dir.grant(b, vb, "Admin", true)

	ra, ca := dial(t, base+"/api/events", bearer(ta))
	if ca == nil {
		t.Fatalf("status %d", ra.StatusCode)
	}
	for k, want := range map[string]string{
		"Content-Type": "text/event-stream", "Cache-Control": "no-store", "X-Accel-Buffering": "no",
	} {
		if got := ra.Header.Get(k); got != want {
			t.Fatalf("%s = %q, want %q", k, got, want)
		}
	}
	_, cb := dial(t, base+"/api/events", map[string]string{"X-Lumi-Token": tb})
	if ev := ca.next(t); ev[0] != EventHello || !strings.Contains(ev[1], va.String()) || strings.Contains(ev[1], vb.String()) {
		t.Fatalf("A hello: %v", ev)
	}
	if ev := cb.next(t); ev[0] != EventHello || !strings.Contains(ev[1], vb.String()) || strings.Contains(ev[1], va.String()) {
		t.Fatalf("B hello: %v", ev)
	}

	time.Sleep(2500 * time.Millisecond) // past WriteTimeout
	br.VaultHead(va, 7)
	if ev := ca.next(t); ev[0] != EventVaultHead || ev[1] != fmt.Sprintf(`{"vault_id":"%s","seq":7}`, va) {
		t.Fatalf("A head: %v", ev)
	}
	br.VaultHead(vb, 3)
	if ev := cb.next(t); ev[0] != EventVaultHead || ev[1] != fmt.Sprintf(`{"vault_id":"%s","seq":3}`, vb) {
		t.Fatalf("B got %v; must only ever see its own vault", ev)
	}
}

// ?token= is never accepted on /api/events (no token in URLs).
func TestHTTP_QueryTokenRejected(t *testing.T) {
	br := NewBroker(testConfig(), newMemDir(), nil, zerolog.Nop())
	base := startFeedServer(t, br)
	_, tok := account(t)
	resp, c := dial(t, base+"/api/events?token="+tok, nil)
	if c != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", resp.StatusCode)
	}
	if resp, _ := dial(t, base+"/api/events", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no token: %d", resp.StatusCode)
	}
}

// The 17th concurrent stream gets 429 too_many_streams; the open bucket
// answers 429 with Retry-After.
func TestHTTP_Limits(t *testing.T) {
	cfg := testConfig()
	cfg.MaxStreamsPerUser = 16
	br := NewBroker(cfg, newMemDir(), nil, zerolog.Nop())
	base := startFeedServer(t, br)
	_, tok := account(t)
	for i := 0; i < 16; i++ {
		if resp, c := dial(t, base+"/api/events", bearer(tok)); c == nil {
			t.Fatalf("stream %d: %d", i, resp.StatusCode)
		}
	}
	resp, _ := dial(t, base+"/api/events", bearer(tok))
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") != "30" || !strings.Contains(string(body), "too_many_streams") {
		t.Fatalf("17th: %d %s", resp.StatusCode, body)
	}

	// Open-rate bucket (20/min) on a fresh account with a high cap.
	cfg2 := testConfig()
	cfg2.MaxStreamsPerUser = 100
	br2 := NewBroker(cfg2, newMemDir(), nil, zerolog.Nop())
	base2 := startFeedServer(t, br2)
	_, tok2 := account(t)
	for i := 0; i < 20; i++ {
		if resp, c := dial(t, base2+"/api/events", bearer(tok2)); c == nil {
			t.Fatalf("open %d: %d", i, resp.StatusCode)
		}
	}
	resp, _ = dial(t, base2+"/api/events", bearer(tok2))
	body, _ = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" || !strings.Contains(string(body), "rate_limited") {
		t.Fatalf("21st open: %d %q %s", resp.StatusCode, resp.Header.Get("Retry-After"), body)
	}
}

// Logout through auth.Service publishes session.ended and the stream
// closes at once; the re-check catches a session deleted behind auth's
// back within one interval.
func TestHTTP_LogoutAndOutOfBandRevocation(t *testing.T) {
	svc := testAuth(t)
	cfg := testConfig()
	cfg.Recheck = 100 * time.Millisecond
	br := NewBroker(cfg, newMemDir(), svc.Check, zerolog.Nop())
	svc.SetSessionListener(br)
	t.Cleanup(func() { svc.SetSessionListener(nil) })
	base := startFeedServer(t, br)

	_, tok := account(t)
	_, c := dial(t, base+"/api/events", bearer(tok))
	if ev := c.next(t); ev[0] != EventHello {
		t.Fatalf("%v", ev)
	}
	if err := svc.Logout(context.Background(), tok); err != nil {
		t.Fatal(err)
	}
	if ev := c.next(t); ev[0] != EventSessionEnded || ev[1] != `{"reason":"revoked"}` {
		t.Fatalf("after logout: %v", ev)
	}
	c.closed(t)

	_, tok2 := account(t)
	_, c2 := dial(t, base+"/api/events", bearer(tok2))
	c2.next(t)
	_ = sessions.DeleteSession(context.Background(), tok2) // revoked out of band
	if ev := c2.next(t); ev[0] != EventSessionEnded || ev[1] != `{"reason":"revoked"}` {
		t.Fatalf("after out-of-band revoke: %v", ev)
	}
	c2.closed(t)
}
