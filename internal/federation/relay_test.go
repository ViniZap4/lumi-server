package federation

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/ViniZap4/lumi-server/internal/crdt"
	"github.com/ViniZap4/lumi-server/internal/domain"
)

// ---- protocol ------------------------------------------------------------------

func TestFrameCodec_RoundTrips(t *testing.T) {
	manifest := []NoteMeta{
		{ID: "alpha", Path: "alpha.md", Title: "Alpha"},
		{ID: "beta", Path: "sub/beta.md", Title: "Beta β"},
	}
	f, err := DecodeFrame(EncodeManifest(manifest))
	if err != nil || f.Type != frameManifest || len(f.Manifest) != 2 || f.Manifest[1].Title != "Beta β" {
		t.Fatalf("manifest round-trip: %+v %v", f, err)
	}

	payload := []byte{0, 1, 2, 3, 250}
	f, err = DecodeFrame(EncodeNoteSync("alpha", payload))
	if err != nil || f.Type != frameNoteSync || f.NoteID != "alpha" || string(f.Payload) != string(payload) {
		t.Fatalf("noteSync round-trip: %+v %v", f, err)
	}

	f, err = DecodeFrame(EncodeNoteAnnounce(NoteMeta{ID: "gamma", Path: "g.md", Title: "Γ"}))
	if err != nil || f.Type != frameNoteAnnounce || f.Note.ID != "gamma" {
		t.Fatalf("announce round-trip: %+v %v", f, err)
	}

	if _, err := DecodeFrame([]byte{99}); err == nil {
		t.Fatalf("unknown frame type must error")
	}
	if _, err := DecodeFrame(EncodeNoteSync("alpha", payload)[:3]); err == nil {
		t.Fatalf("truncated frame must error")
	}
}

// ---- nonce store ------------------------------------------------------------------

func TestNonceStore_SingleUseAndBinding(t *testing.T) {
	ns := newNonceStore()
	vaultID := uuid.New()

	n1 := ns.mint(vaultID, "https://f.example")
	if !ns.consume(n1, vaultID, "https://f.example") {
		t.Fatalf("fresh nonce must consume")
	}
	if ns.consume(n1, vaultID, "https://f.example") {
		t.Fatalf("nonce must be single-use")
	}

	n2 := ns.mint(vaultID, "https://f.example")
	if ns.consume(n2, uuid.New(), "https://f.example") {
		t.Fatalf("wrong vault must fail")
	}
	n3 := ns.mint(vaultID, "https://f.example")
	if ns.consume(n3, vaultID, "https://other.example") {
		t.Fatalf("wrong peer must fail")
	}

	ns.now = func() time.Time { return time.Now().Add(2 * nonceTTL) }
	n4 := ""
	func() {
		defer func() { ns.now = time.Now }()
		n4 = ns.mint(vaultID, "https://f.example")
		_ = n4
	}()
	nExp := ns.mint(vaultID, "https://f.example")
	ns.now = func() time.Time { return time.Now().Add(2 * nonceTTL) }
	if ns.consume(nExp, vaultID, "https://f.example") {
		t.Fatalf("expired nonce must fail")
	}
}

// ---- in-memory transport ------------------------------------------------------------

type pipeState struct {
	once   sync.Once
	closed chan struct{}
}

type pipeConn struct {
	in    chan []byte
	out   chan []byte
	state *pipeState
}

func newPipePair() (*pipeConn, *pipeConn) {
	st := &pipeState{closed: make(chan struct{})}
	a2b := make(chan []byte, 1024)
	b2a := make(chan []byte, 1024)
	a := &pipeConn{in: b2a, out: a2b, state: st}
	b := &pipeConn{in: a2b, out: b2a, state: st}
	return a, b
}

func (p *pipeConn) ReadMessage() (int, []byte, error) {
	select {
	case msg := <-p.in:
		return binaryMessage, msg, nil
	case <-p.state.closed:
		return 0, nil, io.EOF
	}
}

func (p *pipeConn) WriteMessage(_ int, data []byte) error {
	select {
	case p.out <- data:
		return nil
	case <-p.state.closed:
		return io.ErrClosedPipe
	}
}

func (p *pipeConn) Close() error {
	p.state.once.Do(func() { close(p.state.closed) })
	return nil
}

// ---- in-memory CRDT store -----------------------------------------------------------

type memSnapRepo struct {
	mu      sync.Mutex
	snaps   map[string][]byte
	updates map[string][]crdt.UpdateRow
	nextID  int64
}

func newMemSnapRepo() *memSnapRepo {
	return &memSnapRepo{snaps: map[string][]byte{}, updates: map[string][]crdt.UpdateRow{}}
}

func snKey(vaultID uuid.UUID, noteID string) string { return vaultID.String() + "|" + noteID }

func (m *memSnapRepo) GetSnapshot(_ context.Context, vaultID uuid.UUID, noteID string) (crdt.SnapshotRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.snaps[snKey(vaultID, noteID)]
	if !ok {
		return crdt.SnapshotRow{}, domain.ErrNotFound
	}
	return crdt.SnapshotRow{State: s}, nil
}

func (m *memSnapRepo) UpsertSnapshot(_ context.Context, vaultID uuid.UUID, noteID string, state []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.snaps[snKey(vaultID, noteID)] = state
	return nil
}

func (m *memSnapRepo) AppendUpdate(_ context.Context, vaultID uuid.UUID, noteID string, update []byte, _ uuid.UUID, originKind string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	k := snKey(vaultID, noteID)
	m.updates[k] = append(m.updates[k], crdt.UpdateRow{ID: m.nextID, Update: update, OriginKind: originKind})
	return m.nextID, nil
}

func (m *memSnapRepo) ListUpdatesSince(_ context.Context, vaultID uuid.UUID, noteID string, sinceID int64, _ int) ([]crdt.UpdateRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []crdt.UpdateRow
	for _, u := range m.updates[snKey(vaultID, noteID)] {
		if u.ID > sinceID {
			out = append(out, u)
		}
	}
	return out, nil
}

func (m *memSnapRepo) CountUpdates(_ context.Context, vaultID uuid.UUID, noteID string) (int, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := m.updates[snKey(vaultID, noteID)]
	var bytes int64
	for _, u := range rows {
		bytes += int64(len(u.Update))
	}
	return len(rows), bytes, nil
}

func (m *memSnapRepo) DeleteUpdatesUpTo(_ context.Context, vaultID uuid.UUID, noteID string, maxID int64) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := snKey(vaultID, noteID)
	var kept []crdt.UpdateRow
	var deleted int64
	for _, u := range m.updates[k] {
		if u.ID <= maxID {
			deleted++
		} else {
			kept = append(kept, u)
		}
	}
	m.updates[k] = kept
	return deleted, nil
}

func (m *memSnapRepo) HighestUpdateID(_ context.Context, vaultID uuid.UUID, noteID string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rows := m.updates[snKey(vaultID, noteID)]
	if len(rows) == 0 {
		return 0, nil
	}
	return rows[len(rows)-1].ID, nil
}

// ---- note repo + mirror fakes ---------------------------------------------------------

type memNoteRepo struct {
	mu   sync.Mutex
	rows map[string]domain.Note
}

func newMemNoteRepo() *memNoteRepo { return &memNoteRepo{rows: map[string]domain.Note{}} }

func (m *memNoteRepo) Upsert(_ context.Context, n domain.Note) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[snKey(n.VaultID, n.ID)] = n
	return nil
}

func (m *memNoteRepo) Get(_ context.Context, vaultID uuid.UUID, id string) (domain.Note, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n, ok := m.rows[snKey(vaultID, id)]
	if !ok {
		return domain.Note{}, domain.ErrNotFound
	}
	return n, nil
}

func (m *memNoteRepo) delete(vaultID uuid.UUID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := snKey(vaultID, id)
	if _, ok := m.rows[k]; !ok {
		return domain.ErrNotFound
	}
	delete(m.rows, k)
	return nil
}

func (m *memNoteRepo) ListForVault(_ context.Context, vaultID uuid.UUID, limit, offset int) ([]domain.Note, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var all []domain.Note
	for _, n := range m.rows {
		if n.VaultID == vaultID {
			all = append(all, n)
		}
	}
	if offset >= len(all) {
		return nil, nil
	}
	end := offset + limit
	if end > len(all) {
		end = len(all)
	}
	return all[offset:end], nil
}

type mirrorCapture struct {
	mu    sync.Mutex
	texts map[string]string
}

func newMirrorCapture() *mirrorCapture { return &mirrorCapture{texts: map[string]string{}} }

func (m *mirrorCapture) fn(_ context.Context, vaultID uuid.UUID, noteID, text string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.texts[snKey(vaultID, noteID)] = text
	return nil
}

func (m *mirrorCapture) get(vaultID uuid.UUID, noteID string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.texts[snKey(vaultID, noteID)]
	return t, ok
}

// ---- e2e session pair -------------------------------------------------------------------

type relaySide struct {
	registry *crdt.Registry
	repo     *memSnapRepo
	notes    *memNoteRepo
	mirror   *mirrorCapture
	links    *Links
}

func newRelaySide(t *testing.T) *relaySide {
	t.Helper()
	repo := newMemSnapRepo()
	side := &relaySide{
		registry: crdt.NewRegistry(repo),
		repo:     repo,
		notes:    newMemNoteRepo(),
		mirror:   newMirrorCapture(),
	}
	side.links = NewLinks(context.Background(), RelayDeps{
		Registry: side.registry,
		Notes:    side.notes,
		Mirror:   side.mirror.fn,
		Delete: func(_ context.Context, vaultID uuid.UUID, noteID string) error {
			return side.notes.delete(vaultID, noteID)
		},
		Log: zerolog.Nop(),
	})
	side.registry.SetOnPersist(side.links.OnPersist)
	return side
}

func (rs *relaySide) seedNote(t *testing.T, vaultID uuid.UUID, id, path, title, body string) {
	t.Helper()
	if err := rs.notes.Upsert(context.Background(), domain.Note{
		ID: id, VaultID: vaultID, Path: path, Title: title,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := rs.registry.InitFromText(context.Background(), vaultID, id, body, uuid.Nil, "seed"); err != nil {
		t.Fatal(err)
	}
}

// localEdit simulates a local client write: text diff → persist (fires the
// hook → relays to peers).
func (rs *relaySide) localEdit(t *testing.T, vaultID uuid.UUID, noteID, newText string) {
	t.Helper()
	doc, err := rs.registry.LoadDoc(context.Background(), vaultID, noteID)
	if err != nil {
		t.Fatal(err)
	}
	defer doc.Close()
	update, err := doc.ApplyTextDiff(newText, "web")
	if err != nil {
		t.Fatal(err)
	}
	if err := rs.registry.PersistChange(context.Background(), vaultID, noteID, update, uuid.Nil, "web", doc); err != nil {
		t.Fatal(err)
	}
}

func (rs *relaySide) text(t *testing.T, vaultID uuid.UUID, noteID string) string {
	t.Helper()
	doc, err := rs.registry.LoadDoc(context.Background(), vaultID, noteID)
	if err != nil {
		t.Fatal(err)
	}
	defer doc.Close()
	text, err := doc.Text()
	if err != nil {
		t.Fatal(err)
	}
	return text
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func TestRelay_EndToEndConvergence(t *testing.T) {
	vaultID := uuid.New()
	home := newRelaySide(t)
	follower := newRelaySide(t)

	// Home starts with one note; follower starts with a note home lacks.
	home.seedNote(t, vaultID, "alpha", "alpha.md", "Alpha", "hello from home")
	follower.seedNote(t, vaultID, "beta", "beta.md", "Beta", "hello from follower")

	homeConn, followerConn := newPipePair()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	homeSess := home.links.NewSession(ctx, homeConn, vaultID, "https://follower.example", "home")
	followerSess := follower.links.NewSession(ctx, followerConn, vaultID, "https://home.example", "follower")

	go func() { _ = homeSess.Run() }()
	go func() { _ = followerSess.Run() }()

	// Initial reconciliation: alpha flows home→follower (row + content +
	// FS mirror), beta flows follower→home via announce.
	waitFor(t, "alpha row on follower", func() bool {
		_, err := follower.notes.Get(context.Background(), vaultID, "alpha")
		return err == nil
	})
	waitFor(t, "alpha content on follower", func() bool {
		text, ok := follower.mirror.get(vaultID, "alpha")
		return ok && text == "hello from home"
	})
	waitFor(t, "beta row on home", func() bool {
		_, err := home.notes.Get(context.Background(), vaultID, "beta")
		return err == nil
	})
	waitFor(t, "beta content on home", func() bool {
		text, ok := home.mirror.get(vaultID, "beta")
		return ok && text == "hello from follower"
	})

	// Live edit on home propagates to follower.
	home.localEdit(t, vaultID, "alpha", "hello from home, edited")
	waitFor(t, "alpha live edit on follower", func() bool {
		text, ok := follower.mirror.get(vaultID, "alpha")
		return ok && text == "hello from home, edited"
	})

	// Live edit on follower propagates to home (and does not bounce back
	// in a broken state — final text must converge on both sides).
	follower.localEdit(t, vaultID, "beta", "hello from follower, edited")
	waitFor(t, "beta live edit on home", func() bool {
		text, ok := home.mirror.get(vaultID, "beta")
		return ok && text == "hello from follower, edited"
	})

	if got := follower.text(t, vaultID, "alpha"); got != "hello from home, edited" {
		t.Fatalf("follower alpha state = %q", got)
	}
	if got := home.text(t, vaultID, "beta"); got != "hello from follower, edited" {
		t.Fatalf("home beta state = %q", got)
	}

	// Deletion on home propagates to the follower (idempotent on repeat).
	if err := home.notes.delete(vaultID, "alpha"); err != nil {
		t.Fatal(err)
	}
	home.links.NoteDeleted(vaultID, "alpha")
	waitFor(t, "alpha deletion on follower", func() bool {
		_, err := follower.notes.Get(context.Background(), vaultID, "alpha")
		return errors.Is(err, domain.ErrNotFound)
	})
}

func TestRelay_NoteCreatedFansOutToPeers(t *testing.T) {
	vaultID := uuid.New()
	home := newRelaySide(t)
	follower := newRelaySide(t)

	homeConn, followerConn := newPipePair()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	homeSess := home.links.NewSession(ctx, homeConn, vaultID, "https://follower.example", "home")
	followerSess := follower.links.NewSession(ctx, followerConn, vaultID, "https://home.example", "follower")
	go func() { _ = homeSess.Run() }()
	go func() { _ = followerSess.Run() }()

	// Simulate notes.Service.Create on home after the link is up.
	home.seedNote(t, vaultID, "gamma", "gamma.md", "Gamma", "fresh note")
	home.links.NoteCreated(vaultID, "gamma", "gamma.md", "Gamma")

	waitFor(t, "gamma on follower", func() bool {
		text, ok := follower.mirror.get(vaultID, "gamma")
		return ok && text == "fresh note"
	})
	n, err := follower.notes.Get(context.Background(), vaultID, "gamma")
	if err != nil || n.Path != "gamma.md" || n.Title != "Gamma" {
		t.Fatalf("gamma metadata on follower: %+v %v", n, err)
	}
}

func TestRelay_RejectsHostileMetadata(t *testing.T) {
	side := newRelaySide(t)
	vaultID := uuid.New()
	sess := side.links.NewSession(context.Background(), &pipeConn{state: &pipeState{closed: make(chan struct{})}}, vaultID, "https://p.example", "home")

	for _, m := range []NoteMeta{
		{ID: "../escape", Path: "x.md", Title: "t"},
		{ID: "ok", Path: "../../etc/passwd", Title: "t"},
		{ID: "ok", Path: "/abs.md", Title: "t"},
		{ID: "", Path: "x.md", Title: "t"},
		{ID: ".hidden", Path: "x.md", Title: "t"},
	} {
		if err := sess.ensureNote(m); err == nil {
			t.Fatalf("hostile meta accepted: %+v", m)
		}
	}
	if _, err := side.notes.ListForVault(context.Background(), vaultID, 10, 0); err != nil {
		t.Fatal(err)
	}
	if rows, _ := side.notes.ListForVault(context.Background(), vaultID, 10, 0); len(rows) != 0 {
		t.Fatalf("hostile meta created rows: %v", rows)
	}
}

func TestBackoff_CapsAndGrows(t *testing.T) {
	prev := time.Duration(0)
	for attempt := 1; attempt <= 10; attempt++ {
		d := backoff(attempt)
		if d <= 0 || d > reconnectMax+reconnectMax/5 {
			t.Fatalf("attempt %d: backoff %v out of bounds", attempt, d)
		}
		if attempt <= 4 && d < prev/2 {
			t.Fatalf("attempt %d: backoff shrank too fast: %v after %v", attempt, d, prev)
		}
		prev = d
	}
	_ = fmt.Sprintf("%v", prev)
}
