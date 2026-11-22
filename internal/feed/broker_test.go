package feed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/vaults"
)

// ---- fakes ---------------------------------------------------------------------------

// memDir is an in-memory Directory: grants[user][vault] = access.
type memDir struct {
	mu     sync.Mutex
	grants map[uuid.UUID]map[uuid.UUID]VaultAccess
	heads  map[uuid.UUID]int64
	gate   chan struct{} // when set, Readable waits on it once
	failRd bool
	hidden map[uuid.UUID]bool // vaults Readable omits (simulates a stale snapshot)
}

func newMemDir() *memDir {
	return &memDir{grants: map[uuid.UUID]map[uuid.UUID]VaultAccess{}, heads: map[uuid.UUID]int64{}}
}

func (d *memDir) grant(user, vault uuid.UUID, role string, canEdit bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.grants[user] == nil {
		d.grants[user] = map[uuid.UUID]VaultAccess{}
	}
	d.grants[user][vault] = VaultAccess{VaultID: vault, Role: role, CanEdit: canEdit}
}

func (d *memDir) revoke(user, vault uuid.UUID) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.grants[user], vault)
}

func (d *memDir) setHead(vault uuid.UUID, seq int64) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.heads[vault] = seq
}

func (d *memDir) Readable(ctx context.Context, user uuid.UUID) ([]VaultAccess, error) {
	d.mu.Lock()
	gate := d.gate
	d.gate = nil
	fail := d.failRd
	d.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if fail {
		return nil, errors.New("db down")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []VaultAccess
	for _, a := range d.grants[user] {
		if d.hidden[a.VaultID] {
			continue
		}
		a.Seq = d.heads[a.VaultID]
		out = append(out, a)
	}
	return out, nil
}

func (d *memDir) Access(_ context.Context, user, vault uuid.UUID) (VaultAccess, bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	a, ok := d.grants[user][vault]
	a.Seq = d.heads[vault]
	return a, ok, nil
}

// capWriter records frames; ping frames are recorded as name "ping".
type capWriter struct {
	ch    chan frame
	block chan struct{} // when non-nil, every write waits on it
}

func newCapWriter() *capWriter { return &capWriter{ch: make(chan frame, 4096)} }

func (w *capWriter) event(name string, data []byte) error {
	if w.block != nil {
		<-w.block
	}
	w.ch <- frame{name, append([]byte(nil), data...)}
	return nil
}

func (w *capWriter) ping() error {
	w.ch <- frame{"ping", nil}
	return nil
}

// next returns the next non-ping frame or fails after d.
func (w *capWriter) next(t *testing.T, d time.Duration) frame {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case f := <-w.ch:
			if f.name == "ping" {
				continue
			}
			return f
		case <-deadline:
			t.Fatalf("no frame within %v", d)
		}
	}
}

// quiet asserts no non-ping frame arrives within d.
func (w *capWriter) quiet(t *testing.T, d time.Duration) {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case f := <-w.ch:
			if f.name != "ping" {
				t.Fatalf("unexpected frame %s %s", f.name, f.data)
			}
		case <-deadline:
			return
		}
	}
}

func testConfig() Config {
	c := DefaultConfig()
	c.HeadInterval = 20 * time.Millisecond
	c.Ping = time.Hour
	c.Recheck = time.Hour
	c.MaxLifetime = time.Hour
	c.ResolveTimeout = time.Second
	return c
}

type stream struct {
	sub  *Subscriber
	w    *capWriter
	done chan struct{}
}

func (st *stream) waitDone(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case <-st.done:
	case <-time.After(d):
		t.Fatalf("stream did not stop within %v", d)
	}
}

func open(t *testing.T, b *Broker, user uuid.UUID, token string) *stream {
	t.Helper()
	sub, err := b.Open(user, token)
	if err != nil {
		t.Fatal(err)
	}
	return serve(b, sub, newCapWriter())
}

func serve(b *Broker, sub *Subscriber, w *capWriter) *stream {
	st := &stream{sub: sub, w: w, done: make(chan struct{})}
	go func() {
		defer close(st.done)
		b.Serve(sub, w)
	}()
	return st
}

func hello(t *testing.T, st *stream) helloPayload {
	t.Helper()
	f := st.w.next(t, time.Second)
	if f.name != EventHello {
		t.Fatalf("first frame %s, want hello", f.name)
	}
	var h helloPayload
	if err := json.Unmarshal(f.data, &h); err != nil {
		t.Fatal(err)
	}
	return h
}

func newTestBroker(t *testing.T, dir Directory, check SessionChecker, cfg Config) *Broker {
	t.Helper()
	b := NewBroker(cfg, dir, check, zerolog.Nop())
	t.Cleanup(b.Close)
	return b
}

func expect(t *testing.T, f frame, name, data string) {
	t.Helper()
	if f.name != name || string(f.data) != data {
		t.Fatalf("got %s %s, want %s %s", f.name, f.data, name, data)
	}
}

// ---- tests ---------------------------------------------------------------------------

// Mandatory (SPEC-LIVROS §3.6): account B never receives anything about
// account A's vault — heads, updates, access changes, deletion.
func TestIsolation_AccountBNeverSeesVaultOfA(t *testing.T) {
	dir := newMemDir()
	a, bUser := uuid.New(), uuid.New()
	va, vb := uuid.New(), uuid.New()
	dir.grant(a, va, "Admin", true)
	dir.grant(bUser, vb, "Admin", true)
	br := newTestBroker(t, dir, nil, testConfig())

	sa := open(t, br, a, "tok-a")
	sb := open(t, br, bUser, "tok-b")
	ha, hb := hello(t, sa), hello(t, sb)
	if len(ha.Vaults) != 1 || ha.Vaults[0].VaultID != va || len(hb.Vaults) != 1 || hb.Vaults[0].VaultID != vb {
		t.Fatalf("hello sets: a=%+v b=%+v", ha.Vaults, hb.Vaults)
	}

	br.VaultHead(va, 1)
	br.VaultUpdated(va, "name")
	br.AccessChanged(va, a, bUser) // B still has no grant on va
	br.VaultAccessChanged(va)
	br.VaultDeleted(va)

	// A sees its own events; B sees none of them.
	if f := sa.w.next(t, time.Second); f.name != EventVaultUpdated && f.name != EventVaultHead {
		t.Fatalf("A got %s", f.name)
	}
	sb.w.quiet(t, 200*time.Millisecond)
	for _, f := range drain(sa.w) {
		if strings.Contains(string(f.data), vb.String()) {
			t.Fatalf("A received B's vault: %s %s", f.name, f.data)
		}
	}
}

func drain(w *capWriter) []frame {
	var out []frame
	for {
		select {
		case f := <-w.ch:
			out = append(out, f)
		default:
			return out
		}
	}
}

// Wire golden for hello (SPEC-LIVROS §3.3).
func TestHello_Wire(t *testing.T) {
	dir := newMemDir()
	u := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	v1 := uuid.MustParse("aaaaaaaa-0000-0000-0000-000000000001")
	v2 := uuid.MustParse("bbbbbbbb-0000-0000-0000-000000000002")
	dir.grant(u, v2, "Viewer", false)
	dir.grant(u, v1, "Editor", true)
	dir.setHead(v1, 42)
	br := newTestBroker(t, dir, nil, testConfig())
	br.now = func() time.Time { return time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC) }
	st := open(t, br, u, "t")
	expect(t, st.w.next(t, time.Second), EventHello,
		`{"protocol":1,"server_time":"2026-11-22T12:00:00Z","user_id":"11111111-1111-1111-1111-111111111111","vaults":[`+
			`{"vault_id":"aaaaaaaa-0000-0000-0000-000000000001","seq":42,"role":"Editor","can_edit":true},`+
			`{"vault_id":"bbbbbbbb-0000-0000-0000-000000000002","seq":0,"role":"Viewer","can_edit":false}]}`)

	// A user with no vaults gets an empty array, never null.
	st2 := open(t, br, uuid.MustParse("22222222-2222-2222-2222-222222222222"), "t2")
	expect(t, st2.w.next(t, time.Second), EventHello,
		`{"protocol":1,"server_time":"2026-11-22T12:00:00Z","user_id":"22222222-2222-2222-2222-222222222222","vaults":[]}`)
}

// vault.head is coalesced per vault (last wins) and never goes backwards.
func TestVaultHead_CoalescedAndMonotonic(t *testing.T) {
	dir := newMemDir()
	u, v := uuid.New(), uuid.New()
	dir.grant(u, v, "Editor", true)
	dir.setHead(v, 10)
	cfg := testConfig()
	cfg.HeadInterval = 100 * time.Millisecond
	br := newTestBroker(t, dir, nil, cfg)
	st := open(t, br, u, "t")
	hello(t, st)

	br.VaultHead(v, 9) // older than hello: never announced
	st.w.quiet(t, 50*time.Millisecond)
	br.VaultHead(v, 11) // leading edge: immediate
	expect(t, st.w.next(t, time.Second), EventVaultHead, fmt.Sprintf(`{"vault_id":"%s","seq":11}`, v))
	for seq := int64(12); seq <= 20; seq++ {
		br.VaultHead(v, seq)
	}
	br.VaultHead(v, 15) // out-of-order publication
	expect(t, st.w.next(t, time.Second), EventVaultHead, fmt.Sprintf(`{"vault_id":"%s","seq":20}`, v))
	st.w.quiet(t, 150*time.Millisecond)
}

// Removing a member produces vault.revoked fast and stops that vault's
// events for the stream; the other vault keeps flowing.
func TestRevoke_RemovedStopsVaultEvents(t *testing.T) {
	dir := newMemDir()
	u, keep, gone := uuid.New(), uuid.New(), uuid.New()
	dir.grant(u, keep, "Editor", true)
	dir.grant(u, gone, "Editor", true)
	br := newTestBroker(t, dir, nil, testConfig())
	st := open(t, br, u, "t")
	hello(t, st)

	dir.revoke(u, gone)
	start := time.Now()
	br.AccessChanged(gone, u)
	expect(t, st.w.next(t, time.Second), EventVaultRevoked, fmt.Sprintf(`{"vault_id":"%s","reason":"removed"}`, gone))
	if el := time.Since(start); el > time.Second {
		t.Fatalf("revoke took %v (spec: < 1 s)", el)
	}
	br.VaultHead(gone, 5)
	br.VaultUpdated(gone, "name")
	br.VaultHead(keep, 3)
	expect(t, st.w.next(t, time.Second), EventVaultHead, fmt.Sprintf(`{"vault_id":"%s","seq":3}`, keep))
	st.w.quiet(t, 100*time.Millisecond)
}

// Gaining access and changing role both produce vault.access; a repeat
// resolution with no change produces nothing.
func TestAccess_GainAndRoleChange(t *testing.T) {
	dir := newMemDir()
	u, v := uuid.New(), uuid.New()
	br := newTestBroker(t, dir, nil, testConfig())
	st := open(t, br, u, "t")
	hello(t, st)

	br.VaultHead(v, 1) // not readable yet
	dir.grant(u, v, "Viewer", false)
	br.AccessChanged(v, u)
	expect(t, st.w.next(t, time.Second), EventVaultAccess, fmt.Sprintf(`{"vault_id":"%s","role":"Viewer","can_edit":false}`, v))
	br.AccessChanged(v, u)
	st.w.quiet(t, 50*time.Millisecond)
	dir.grant(u, v, "Editor", true)
	br.VaultAccessChanged(v)
	expect(t, st.w.next(t, time.Second), EventVaultAccess, fmt.Sprintf(`{"vault_id":"%s","role":"Editor","can_edit":true}`, v))
	br.VaultHead(v, 2)
	expect(t, st.w.next(t, time.Second), EventVaultHead, fmt.Sprintf(`{"vault_id":"%s","seq":2}`, v))
}

func TestVaultDeletedAndUpdated(t *testing.T) {
	dir := newMemDir()
	u, v := uuid.New(), uuid.New()
	dir.grant(u, v, "Admin", true)
	br := newTestBroker(t, dir, nil, testConfig())
	st := open(t, br, u, "t")
	hello(t, st)
	br.VaultUpdated(v, "name", "federation")
	expect(t, st.w.next(t, time.Second), EventVaultUpdated, fmt.Sprintf(`{"vault_id":"%s","fields":["name","federation"]}`, v))
	br.VaultDeleted(v)
	expect(t, st.w.next(t, time.Second), EventVaultRevoked, fmt.Sprintf(`{"vault_id":"%s","reason":"deleted"}`, v))
	br.VaultUpdated(v, "name")
	st.w.quiet(t, 50*time.Millisecond)
}

// Logout ends exactly the streams of that session, at once.
func TestSessionEnded_OnlyThatSession(t *testing.T) {
	dir := newMemDir()
	u := uuid.New()
	br := newTestBroker(t, dir, nil, testConfig())
	s1 := open(t, br, u, "phone")
	s2 := open(t, br, u, "laptop")
	hello(t, s1)
	hello(t, s2)
	br.SessionEnded("phone", SessionRevoked)
	expect(t, s1.w.next(t, time.Second), EventSessionEnded, `{"reason":"revoked"}`)
	s1.waitDone(t, time.Second)
	s2.w.quiet(t, 50*time.Millisecond)
	if n := br.Streams(u); n != 1 {
		t.Fatalf("streams = %d, want 1", n)
	}
	br.UserSessionsEnded(u, SessionDeleted)
	expect(t, s2.w.next(t, time.Second), EventSessionEnded, `{"reason":"deleted"}`)
	s2.waitDone(t, time.Second)
}

// A token revoked out of band ends the stream at the next re-check.
func TestRecheck_SessionRevokedOutOfBand(t *testing.T) {
	dir := newMemDir()
	u := uuid.New()
	var mu sync.Mutex
	reason := ""
	check := func(_ context.Context, tok string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if tok != "t" {
			t.Errorf("checker got token %q", tok)
		}
		return reason, nil
	}
	cfg := testConfig()
	cfg.Recheck = 30 * time.Millisecond
	br := newTestBroker(t, dir, check, cfg)
	st := open(t, br, u, "t")
	hello(t, st)
	st.w.quiet(t, 100*time.Millisecond) // valid: survives several re-checks
	mu.Lock()
	reason = SessionExpired
	mu.Unlock()
	expect(t, st.w.next(t, time.Second), EventSessionEnded, `{"reason":"expired"}`)
	st.waitDone(t, time.Second)
}

// The periodic re-check heals a missed membership publication.
func TestRecheck_ReconcilesAccess(t *testing.T) {
	dir := newMemDir()
	u, v, w := uuid.New(), uuid.New(), uuid.New()
	dir.grant(u, v, "Editor", true)
	cfg := testConfig()
	cfg.Recheck = 30 * time.Millisecond
	br := newTestBroker(t, dir, nil, cfg)
	st := open(t, br, u, "t")
	hello(t, st)
	dir.revoke(u, v)
	dir.grant(u, w, "Viewer", false)
	got := map[string]string{}
	for i := 0; i < 2; i++ {
		f := st.w.next(t, time.Second)
		got[f.name] = string(f.data)
	}
	if got[EventVaultRevoked] != fmt.Sprintf(`{"vault_id":"%s","reason":"removed"}`, v) ||
		got[EventVaultAccess] != fmt.Sprintf(`{"vault_id":"%s","role":"Viewer","can_edit":false}`, w) {
		t.Fatalf("reconcile frames: %v", got)
	}
}

// Access granted while hello is being computed is not lost: hello's
// snapshot predates the grant, the publication arrives before the stream
// is ready, and the parked re-check emits vault.access after hello.
func TestParkedAccessBeforeHello(t *testing.T) {
	dir := newMemDir()
	u, v := uuid.New(), uuid.New()
	gate := make(chan struct{})
	dir.gate = gate
	dir.hidden = map[uuid.UUID]bool{v: true}
	br := newTestBroker(t, dir, nil, testConfig())
	st := open(t, br, u, "t")
	time.Sleep(20 * time.Millisecond) // Serve is blocked in Readable
	dir.grant(u, v, "Editor", true)
	br.AccessChanged(v, u)
	time.Sleep(20 * time.Millisecond) // the job parks the vault
	close(gate)
	if h := hello(t, st); len(h.Vaults) != 0 {
		t.Fatalf("hello vaults %+v", h.Vaults)
	}
	expect(t, st.w.next(t, time.Second), EventVaultAccess, fmt.Sprintf(`{"vault_id":"%s","role":"Editor","can_edit":true}`, v))
}

// 16 concurrent streams per user; the 17th is refused, and a slot frees
// when a stream ends. Other users are unaffected.
func TestLimits_StreamCap(t *testing.T) {
	dir := newMemDir()
	u := uuid.New()
	cfg := testConfig()
	cfg.OpensPerMinute = 0
	br := newTestBroker(t, dir, nil, cfg)
	var streams []*stream
	for i := 0; i < 16; i++ {
		streams = append(streams, open(t, br, u, fmt.Sprintf("t%d", i)))
	}
	if _, err := br.Open(u, "t16"); !errors.Is(err, ErrTooManyStreams) {
		t.Fatalf("17th open: %v", err)
	}
	if _, err := br.Open(uuid.New(), "other"); err != nil {
		t.Fatalf("other user blocked: %v", err)
	}
	br.SessionEnded("t0", SessionRevoked)
	streams[0].waitDone(t, time.Second)
	if _, err := br.Open(u, "t16"); err != nil {
		t.Fatalf("open after a slot freed: %v", err)
	}
}

func TestLimits_OpenRate(t *testing.T) {
	dir := newMemDir()
	u := uuid.New()
	br := newTestBroker(t, dir, nil, testConfig())
	for i := 0; i < 20; i++ {
		sub, err := br.Open(u, "t")
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		br.unregister(sub)
	}
	_, err := br.Open(u, "t")
	var rl *RateLimitError
	if !errors.As(err, &rl) || rl.RetryAfter <= 0 || rl.RetryAfter > 4*time.Second {
		t.Fatalf("21st open: %v", err)
	}
}

func TestPingAndLifetime(t *testing.T) {
	dir := newMemDir()
	u := uuid.New()
	cfg := testConfig()
	cfg.Ping = 20 * time.Millisecond
	cfg.MaxLifetime = 150 * time.Millisecond
	br := newTestBroker(t, dir, nil, cfg)
	sub, _ := br.Open(u, "t")
	st := serve(br, sub, newCapWriter())
	hello(t, st)
	pings := 0
	deadline := time.After(time.Second)
	for {
		select {
		case f := <-st.w.ch:
			switch f.name {
			case "ping":
				pings++
			case EventReconnect:
				expect(t, f, EventReconnect, `{"after_ms":0}`)
				if pings < 3 {
					t.Fatalf("only %d pings before lifetime end", pings)
				}
				st.waitDone(t, time.Second)
				return
			default:
				t.Fatalf("unexpected %s", f.name)
			}
		case <-deadline:
			t.Fatal("no reconnect at end of lifetime")
		}
	}
}

// A consumer that cannot keep up is disconnected rather than buffered.
func TestSlowConsumerDropped(t *testing.T) {
	dir := newMemDir()
	u := uuid.New()
	cfg := testConfig()
	cfg.Buffer = 4
	br := newTestBroker(t, dir, nil, cfg)
	sub, _ := br.Open(u, "t")
	w := newCapWriter()
	st := serve(br, sub, w)
	hello(t, st)
	for i := 0; i < 50; i++ {
		v := uuid.New()
		dir.grant(u, v, "Viewer", false)
		sub.apply(v, VaultAccess{Role: "Viewer"}, true, ReasonRemoved)
	}
	st.waitDone(t, 2*time.Second)
	if n := br.Streams(u); n != 0 {
		t.Fatalf("dropped stream still registered (%d)", n)
	}
}

// Shutdown tells every stream to reconnect and refuses new ones.
func TestCloseSendsReconnect(t *testing.T) {
	dir := newMemDir()
	br := NewBroker(testConfig(), dir, nil, zerolog.Nop())
	st := open(t, br, uuid.New(), "t")
	hello(t, st)
	br.Close()
	expect(t, st.w.next(t, time.Second), EventReconnect, `{"after_ms":0}`)
	st.waitDone(t, time.Second)
	if _, err := br.Open(uuid.New(), "t"); !errors.Is(err, ErrClosed) {
		t.Fatalf("open after close: %v", err)
	}
}

// A failing directory at hello asks the client to reconnect later.
func TestHelloFailureAsksReconnect(t *testing.T) {
	dir := newMemDir()
	dir.failRd = true
	br := newTestBroker(t, dir, nil, testConfig())
	st := open(t, br, uuid.New(), "t")
	expect(t, st.w.next(t, time.Second), EventReconnect, `{"after_ms":1000}`)
	st.waitDone(t, time.Second)
}

// ---- VaultsDirectory (capability filter on top of vaults.View) ------------------------

type fakeViews struct{ views map[uuid.UUID][]vaults.View }

func (f fakeViews) ListViews(_ context.Context, u uuid.UUID) ([]vaults.View, error) {
	return f.views[u], nil
}

func (f fakeViews) GetView(_ context.Context, u, v uuid.UUID) (vaults.View, error) {
	for _, x := range f.views[u] {
		if x.Vault.ID == v {
			return x, nil
		}
	}
	return vaults.View{}, domain.ErrNotFound
}

// Membership alone is not enough: the feed only lists vaults whose role
// grants note.read, and reports can_edit from note.edit.
func TestVaultsDirectory_FiltersByNoteRead(t *testing.T) {
	u := uuid.New()
	readable, blind, editor := uuid.New(), uuid.New(), uuid.New()
	src := fakeViews{views: map[uuid.UUID][]vaults.View{u: {
		{Vault: domain.Vault{ID: readable}, Role: domain.Role{Name: "Viewer", Capabilities: domain.CapabilitySet{domain.CapNoteRead}}, Head: 4},
		{Vault: domain.Vault{ID: blind}, Role: domain.Role{Name: "Auditor", Capabilities: domain.CapabilitySet{domain.CapAuditRead}}},
		{Vault: domain.Vault{ID: editor}, Role: domain.Role{Name: "Admin", Capabilities: domain.CapabilitySet{domain.CapAll}}, Head: 9},
	}}}
	d := VaultsDirectory{Source: src}
	got, err := d.Readable(context.Background(), u)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != (VaultAccess{readable, 4, "Viewer", false}) || got[1] != (VaultAccess{editor, 9, "Admin", true}) {
		t.Fatalf("readable = %+v", got)
	}
	if _, ok, _ := d.Access(context.Background(), u, blind); ok {
		t.Fatal("role without note.read must not be readable")
	}
	if _, ok, err := d.Access(context.Background(), uuid.New(), readable); ok || err != nil {
		t.Fatalf("non-member: ok=%v err=%v", ok, err)
	}
}
