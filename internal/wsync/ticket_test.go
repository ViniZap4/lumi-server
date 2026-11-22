package wsync

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fws "github.com/fasthttp/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/crdt"
	"github.com/ViniZap4/lumi-server/internal/domain"
)

// ---- TicketStore unit tests ----------------------------------------------------

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newClockedStore() (*TicketStore, *fakeClock) {
	clk := &fakeClock{t: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}
	s := NewTicketStore()
	s.now = clk.now
	return s, clk
}

func testBinding() TicketBinding {
	return TicketBinding{UserID: uuid.New(), Session: "sess", VaultID: uuid.New(), NoteID: "n1"}
}

func TestTicketStore_IssueFormatAndSingleUse(t *testing.T) {
	s, clk := newClockedStore()
	b := testBinding()
	tk, exp, err := s.Issue(b)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(tk)
	if err != nil || len(raw) < 32 {
		t.Fatalf("ticket %q: %d bytes (%v), want ≥32 base64url", tk, len(raw), err)
	}
	if !exp.Equal(clk.now().Add(TicketTTL)) {
		t.Fatalf("expiry %v, want now+%v", exp, TicketTTL)
	}
	got, err := s.Consume(tk)
	if err != nil || got != b {
		t.Fatalf("consume = %+v, %v; want %+v", got, err, b)
	}
	if _, err := s.Consume(tk); !errors.Is(err, ErrTicketInvalid) {
		t.Fatalf("reuse err = %v, want ErrTicketInvalid", err)
	}
	if _, err := s.Consume("not-a-ticket"); !errors.Is(err, ErrTicketInvalid) {
		t.Fatalf("unknown err = %v", err)
	}
}

func TestTicketStore_StoresOnlyHashes(t *testing.T) {
	s, _ := newClockedStore()
	tk, _, _ := s.Issue(testBinding())
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.entries {
		if bytes.Contains(k[:], []byte(tk)) || k != hashTicket(tk) {
			t.Fatal("table must be keyed by SHA-256 of the ticket")
		}
	}
}

func TestTicketStore_Expiry(t *testing.T) {
	s, clk := newClockedStore()
	tk, _, _ := s.Issue(testBinding())
	clk.advance(TicketTTL - time.Millisecond)
	tk2, _, _ := s.Issue(testBinding())
	if _, err := s.Consume(tk2); err != nil {
		t.Fatalf("fresh ticket: %v", err)
	}
	clk.advance(time.Millisecond)
	if _, err := s.Consume(tk); !errors.Is(err, ErrTicketInvalid) {
		t.Fatalf("expired ticket err = %v, want ErrTicketInvalid", err)
	}
}

func TestTicketStore_BoundsAndSweep(t *testing.T) {
	s, clk := newClockedStore()
	s.max = 3
	s.maxPerUser = 2
	b := testBinding()
	for i := 0; i < 2; i++ {
		if _, _, err := s.Issue(b); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.Issue(b); !errors.Is(err, ErrTicketUserLimit) {
		t.Fatalf("per-user cap err = %v", err)
	}
	if _, _, err := s.Issue(testBinding()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Issue(testBinding()); !errors.Is(err, ErrTicketCapacity) {
		t.Fatalf("global cap err = %v", err)
	}
	// Expired entries are swept to make room.
	clk.advance(TicketTTL)
	if _, _, err := s.Issue(b); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
	if n := s.Len(); n != 1 {
		t.Fatalf("Len = %d after sweep, want 1", n)
	}
	s.mu.Lock()
	if len(s.perUser) != 1 {
		t.Errorf("perUser not swept: %v", s.perUser)
	}
	s.mu.Unlock()
}

func TestTicketStore_ConcurrentConsumeExactlyOnce(t *testing.T) {
	s, _ := newClockedStore()
	for round := 0; round < 50; round++ {
		tk, _, _ := s.Issue(testBinding())
		var wins atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := s.Consume(tk); err == nil {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("round %d: %d consumers won, want exactly 1", round, wins.Load())
		}
	}
}

// ---- HTTP + WS end-to-end --------------------------------------------------------

type ticketEnv struct {
	base    string // ws://host:port
	vault   uuid.UUID
	handler *Handler

	mu     sync.Mutex
	tokens map[string]uuid.UUID
}

func (e *ticketEnv) logout(token string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.tokens, token)
}

func (e *ticketEnv) lookup(token string) (uuid.UUID, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	uid, ok := e.tokens[token]
	return uid, ok
}

func startTicketServer(t *testing.T, tokens map[string]uuid.UUID, res stubResolver, notes map[string]bool) *ticketEnv {
	t.Helper()
	env := &ticketEnv{vault: uuid.New(), tokens: tokens}
	hub := NewHub(crdt.NewRegistry(newMemRepo()))
	t.Cleanup(hub.Close)
	authn := func(_ context.Context, tok string) (uuid.UUID, error) {
		if uid, ok := env.lookup(tok); ok {
			return uid, nil
		}
		return uuid.Nil, domain.ErrTokenInvalid
	}
	exists := func(_ context.Context, _ uuid.UUID, id string) error {
		if notes[id] {
			return nil
		}
		return domain.ErrNotFound
	}
	h := NewHandler(hub, res, nil, authn, exists)
	env.handler = h
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	h.Register(app.Group("/api"))
	// Stand-in for auth.Required: binds session + user under the same
	// Locals keys the real middleware uses.
	authed := app.Group("/api", func(c *fiber.Ctx) error {
		tok := c.Get("X-Lumi-Token")
		uid, ok := env.lookup(tok)
		if !ok {
			return c.SendStatus(fiber.StatusUnauthorized)
		}
		c.Locals("auth.session", &domain.Session{Token: tok, UserID: uid})
		c.Locals("auth.user", &domain.User{ID: uid})
		return c.Next()
	})
	h.RegisterTicket(authed)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = app.Listener(ln) }()
	t.Cleanup(func() { _ = app.Shutdown() })
	env.base = "ws://" + ln.Addr().String()
	return env
}

func (e *ticketEnv) mint(t *testing.T, token, note string) (int, ticketResponse) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost,
		"http"+e.base[2:]+"/api/vaults/"+e.vault.String()+"/notes/"+note+"/ws-ticket", nil)
	req.Header.Set("X-Lumi-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out ticketResponse
	if resp.StatusCode == http.StatusCreated {
		if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
			t.Errorf("Cache-Control = %q, want no-store", cc)
		}
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("decode %s: %v", body, err)
		}
	}
	return resp.StatusCode, out
}

// dialTicket returns 0 when the session is accepted (first frame is
// SyncStep1), else the close code.
func (e *ticketEnv) dialTicket(t *testing.T, note, ticket string, hdr http.Header) int {
	t.Helper()
	url := e.base + "/api/vaults/" + e.vault.String() + "/notes/" + note + "/sync?ticket=" + ticket
	conn, resp, err := (&fws.Dialer{HandshakeTimeout: 2 * time.Second}).Dial(url, hdr)
	if err != nil {
		code := 0
		if resp != nil {
			code = resp.StatusCode
		}
		t.Fatalf("dial (HTTP %d): %v", code, err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		var ce *fws.CloseError
		if errors.As(err, &ce) {
			return ce.Code
		}
		t.Fatalf("read: %v", err)
	}
	if m, derr := DecodeMessage(msg); derr != nil || m.Type != MessageSync || m.SyncSub != SyncStep1 {
		t.Fatalf("first frame %+v (%v), want SyncStep1", m, derr)
	}
	return 0
}

func newTicketFixture(t *testing.T) (*ticketEnv, uuid.UUID, uuid.UUID) {
	alice, bob := uuid.New(), uuid.New()
	env := startTicketServer(t,
		map[string]uuid.UUID{"alice": alice, "alice-2": alice, "bob": bob, "viewer": uuid.New(), "stranger": uuid.New()},
		stubResolver{alice: {domain.CapNoteEdit}, bob: {domain.CapNoteEdit}},
		map[string]bool{"n1": true, "n2": true})
	return env, alice, bob
}

func TestTicket_MintAndUpgrade(t *testing.T) {
	env, _, _ := newTicketFixture(t)
	before := time.Now()
	status, tr := env.mint(t, "alice", "n1")
	if status != http.StatusCreated {
		t.Fatalf("mint status %d", status)
	}
	if raw, err := base64.RawURLEncoding.DecodeString(tr.Ticket); err != nil || len(raw) < 32 {
		t.Fatalf("ticket %q not ≥32 bytes base64url", tr.Ticket)
	}
	exp, err := time.Parse(time.RFC3339, tr.ExpiresAt)
	if err != nil {
		t.Fatalf("expires_at %q: %v", tr.ExpiresAt, err)
	}
	if d := exp.Sub(before); d < TicketTTL-2*time.Second || d > TicketTTL+time.Second {
		t.Fatalf("expires_at %v is %v from now, want ~%v", exp, d, TicketTTL)
	}
	if got := env.dialTicket(t, "n1", tr.Ticket, nil); got != 0 {
		t.Fatalf("upgrade with fresh ticket closed %d", got)
	}
	if n := env.handler.Tickets().Len(); n != 0 {
		t.Fatalf("ticket table holds %d after consumption", n)
	}
}

func TestTicket_MintGates(t *testing.T) {
	env, _, _ := newTicketFixture(t)
	cases := []struct {
		name, token, note string
		want              int
	}{
		{"no session", "nope", "n1", http.StatusUnauthorized},
		{"non-member", "stranger", "n1", http.StatusForbidden},
		{"viewer lacks note.edit", "viewer", "n1", http.StatusForbidden},
		{"unknown note", "alice", "missing", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, _ := env.mint(t, tc.token, tc.note); got != tc.want {
				t.Fatalf("status %d, want %d", got, tc.want)
			}
		})
	}
	if n := env.handler.Tickets().Len(); n != 0 {
		t.Fatalf("refused mints left %d tickets", n)
	}
}

func TestTicket_Rejections(t *testing.T) {
	t.Run("reuse", func(t *testing.T) {
		env, _, _ := newTicketFixture(t)
		_, tr := env.mint(t, "alice", "n1")
		if got := env.dialTicket(t, "n1", tr.Ticket, nil); got != 0 {
			t.Fatalf("first use closed %d", got)
		}
		if got := env.dialTicket(t, "n1", tr.Ticket, nil); got != CloseUnauthorized {
			t.Fatalf("reuse closed %d, want %d", got, CloseUnauthorized)
		}
	})
	t.Run("expired", func(t *testing.T) {
		env, _, _ := newTicketFixture(t)
		_, tr := env.mint(t, "alice", "n1")
		s := env.handler.Tickets()
		s.mu.Lock()
		s.now = func() time.Time { return time.Now().Add(TicketTTL) }
		s.mu.Unlock()
		if got := env.dialTicket(t, "n1", tr.Ticket, nil); got != CloseUnauthorized {
			t.Fatalf("expired closed %d, want %d", got, CloseUnauthorized)
		}
	})
	t.Run("wrong note consumes the ticket", func(t *testing.T) {
		env, _, _ := newTicketFixture(t)
		_, tr := env.mint(t, "alice", "n1")
		if got := env.dialTicket(t, "n2", tr.Ticket, nil); got != CloseUnauthorized {
			t.Fatalf("wrong note closed %d, want %d", got, CloseUnauthorized)
		}
		if got := env.dialTicket(t, "n1", tr.Ticket, nil); got != CloseUnauthorized {
			t.Fatalf("ticket survived a wrong-note attempt (closed %d)", got)
		}
	})
	t.Run("wrong user header", func(t *testing.T) {
		env, _, _ := newTicketFixture(t)
		_, tr := env.mint(t, "alice", "n1")
		h := http.Header{"X-Lumi-Token": {"bob"}}
		if got := env.dialTicket(t, "n1", tr.Ticket, h); got != CloseUnauthorized {
			t.Fatalf("alice's ticket with bob's token closed %d, want %d", got, CloseUnauthorized)
		}
	})
	t.Run("same user other session header ok", func(t *testing.T) {
		env, _, _ := newTicketFixture(t)
		_, tr := env.mint(t, "alice", "n1")
		h := http.Header{"X-Lumi-Token": {"alice-2"}}
		if got := env.dialTicket(t, "n1", tr.Ticket, h); got != 0 {
			t.Fatalf("closed %d, want accepted", got)
		}
	})
	t.Run("session logged out after mint", func(t *testing.T) {
		env, _, _ := newTicketFixture(t)
		_, tr := env.mint(t, "alice", "n1")
		env.logout("alice")
		if got := env.dialTicket(t, "n1", tr.Ticket, nil); got != CloseUnauthorized {
			t.Fatalf("closed %d, want %d", got, CloseUnauthorized)
		}
	})
	t.Run("capability revoked after mint", func(t *testing.T) {
		alice := uuid.New()
		res := stubResolver{alice: {domain.CapNoteEdit}}
		env := startTicketServer(t, map[string]uuid.UUID{"alice": alice}, res, map[string]bool{"n1": true})
		_, tr := env.mint(t, "alice", "n1")
		res.set(alice, domain.CapabilitySet{domain.CapNoteRead})
		if got := env.dialTicket(t, "n1", tr.Ticket, nil); got != CloseForbidden {
			t.Fatalf("closed %d, want %d", got, CloseForbidden)
		}
	})
	t.Run("garbage", func(t *testing.T) {
		env, _, _ := newTicketFixture(t)
		if got := env.dialTicket(t, "n1", strings.Repeat("A", 43), nil); got != CloseUnauthorized {
			t.Fatalf("closed %d, want %d", got, CloseUnauthorized)
		}
	})
}

// Concurrent upgrades presenting one ticket: exactly one session opens.
func TestTicket_ConcurrentUpgradesExactlyOne(t *testing.T) {
	env, _, _ := newTicketFixture(t)
	_, tr := env.mint(t, "alice", "n1")
	const n = 8
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = env.dialTicket(t, "n1", tr.Ticket, nil)
		}(i)
	}
	wg.Wait()
	accepted := 0
	for _, c := range codes {
		switch c {
		case 0:
			accepted++
		case CloseUnauthorized:
		default:
			t.Fatalf("unexpected close %d", c)
		}
	}
	if accepted != 1 {
		t.Fatalf("%d upgrades accepted with one ticket (codes %v), want 1", accepted, codes)
	}
}

// Logging out the minting session ends a ticket-opened socket on the next
// revalidation (the socket is bound to that session, not just the user).
func TestTicket_SocketBoundToMintingSession(t *testing.T) {
	old := RevalidateInterval
	RevalidateInterval = 50 * time.Millisecond
	t.Cleanup(func() { RevalidateInterval = old })

	env, _, _ := newTicketFixture(t)
	_, tr := env.mint(t, "alice", "n1")
	url := env.base + "/api/vaults/" + env.vault.String() + "/notes/n1/sync?ticket=" + tr.Ticket
	conn, _, err := (&fws.Dialer{}).Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _, _ = conn.ReadMessage() // SyncStep1
	env.logout("alice")
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		_, _, err := conn.ReadMessage()
		if err == nil {
			continue
		}
		var ce *fws.CloseError
		if !errors.As(err, &ce) || ce.Code != CloseUnauthorized {
			t.Fatalf("got %v, want close %d", err, CloseUnauthorized)
		}
		return
	}
}

// ?token= keeps working (deprecated) next to tickets.
func TestTicket_LegacyQueryTokenStillAccepted(t *testing.T) {
	env, _, _ := newTicketFixture(t)
	url := env.base + "/api/vaults/" + env.vault.String() + "/notes/n1/sync?token=alice"
	conn, _, err := (&fws.Dialer{}).Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("legacy ?token= refused: %v", err)
	}
	if m, _ := DecodeMessage(msg); m.Type != MessageSync || m.SyncSub != SyncStep1 {
		t.Fatalf("first frame %+v", m)
	}
}
