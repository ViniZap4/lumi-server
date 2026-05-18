package fswatch

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/ViniZap4/lumi-server/internal/storage/fs"
)

// recorder is a tiny Handler that pushes every dispatched event into a
// channel so tests can assert on what arrived.
type recorder struct {
	ch     chan Event
	count  atomic.Int64
}

func newRecorder() *recorder { return &recorder{ch: make(chan Event, 32)} }

func (r *recorder) HandleFSWrite(_ context.Context, ev Event) {
	r.count.Add(1)
	select {
	case r.ch <- ev:
	default:
	}
}

// waitForEvent polls the recorder for up to d, returning the first
// event that arrives or (Event{}, false) on timeout.
func (r *recorder) waitForEvent(d time.Duration) (Event, bool) {
	select {
	case ev := <-r.ch:
		return ev, true
	case <-time.After(d):
		return Event{}, false
	}
}

// newTestManager spins up an fs.Manager + fswatch.Manager rooted at a
// temp dir with a vault directory pre-created. Returns helpers for
// writing files and tearing down.
func newTestManager(t *testing.T, opts ...Option) (*Manager, *fs.Manager, string, *recorder, func()) {
	t.Helper()
	root := t.TempDir()
	vaultDir := filepath.Join(root, "vault")
	if err := os.MkdirAll(vaultDir, 0o755); err != nil {
		t.Fatal(err)
	}
	fsMgr, err := fs.NewManager(root)
	if err != nil {
		t.Fatal(err)
	}
	rec := newRecorder()
	mgr, err := New(root, fsMgr, rec, zerolog.Nop(), opts...)
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.WatchExistingVaults(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); mgr.Run(ctx) }()

	teardown := func() {
		cancel()
		_ = mgr.Close()
		wg.Wait()
	}
	return mgr, fsMgr, root, rec, teardown
}

func TestExternalWriteFiresEvent(t *testing.T) {
	mgr, _, root, rec, teardown := newTestManager(t, WithDebounce(20*time.Millisecond))
	defer teardown()
	_ = mgr

	notePath := filepath.Join(root, "vault", "note.md")
	if err := os.WriteFile(notePath, []byte("# hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ev, ok := rec.waitForEvent(800 * time.Millisecond)
	if !ok {
		t.Fatalf("no event received within 800ms")
	}
	if ev.VaultSlug != "vault" {
		t.Fatalf("VaultSlug = %q", ev.VaultSlug)
	}
	if ev.RelativePath != "note.md" {
		t.Fatalf("RelativePath = %q", ev.RelativePath)
	}
}

func TestSkipNextSuppressesEvent(t *testing.T) {
	mgr, _, root, rec, teardown := newTestManager(t, WithDebounce(20*time.Millisecond))
	defer teardown()

	notePath := filepath.Join(root, "vault", "self.md")
	mgr.SkipNext(notePath)

	if err := os.WriteFile(notePath, []byte("server-write\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, ok := rec.waitForEvent(300 * time.Millisecond); ok {
		t.Fatalf("expected suppression, got event")
	}
}

func TestSuppressTTLExpires(t *testing.T) {
	mgr, _, root, rec, teardown := newTestManager(t,
		WithDebounce(20*time.Millisecond),
		WithSuppressTTL(50*time.Millisecond),
	)
	defer teardown()

	notePath := filepath.Join(root, "vault", "ttl.md")
	mgr.SkipNext(notePath)

	// Wait past TTL, then write — should now fire.
	time.Sleep(120 * time.Millisecond)
	if err := os.WriteFile(notePath, []byte("late\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, ok := rec.waitForEvent(500 * time.Millisecond); !ok {
		t.Fatalf("expected event after suppression expiry")
	}
}

func TestIgnoresNonMarkdownFiles(t *testing.T) {
	_, _, root, rec, teardown := newTestManager(t, WithDebounce(20*time.Millisecond))
	defer teardown()

	cases := []string{".note.md.swp", "note.md~", "note.tmp", "4913", "note.txt"}
	for _, name := range cases {
		p := filepath.Join(root, "vault", name)
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := rec.waitForEvent(300 * time.Millisecond); ok {
		t.Fatalf("expected no events for ignored filenames")
	}
}

func TestDebounceCoalesces(t *testing.T) {
	_, _, root, rec, teardown := newTestManager(t, WithDebounce(80*time.Millisecond))
	defer teardown()

	notePath := filepath.Join(root, "vault", "burst.md")

	// Simulate vim's atomic-save burst: rapid-fire writes that should
	// fold into a single handler invocation.
	for i := 0; i < 5; i++ {
		_ = os.WriteFile(notePath, []byte("iter\n"), 0o644)
		time.Sleep(10 * time.Millisecond)
	}

	// Wait for the debounce timer to fire.
	if _, ok := rec.waitForEvent(500 * time.Millisecond); !ok {
		t.Fatalf("expected at least one event")
	}
	// Drain anything queued; assert <=1 extra event (some kernels emit
	// CHMOD-style trailing events that fall outside the window).
	count := int64(1)
	for {
		select {
		case <-rec.ch:
			count++
		case <-time.After(200 * time.Millisecond):
			goto done
		}
	}
done:
	if count > 2 {
		t.Fatalf("expected <=2 coalesced events, got %d", count)
	}
}

func TestNewVaultDirAutoWatched(t *testing.T) {
	mgr, _, root, rec, teardown := newTestManager(t, WithDebounce(20*time.Millisecond))
	defer teardown()
	_ = mgr

	// Create a vault dir AFTER startup.
	newVault := filepath.Join(root, "freshvault")
	if err := os.MkdirAll(newVault, 0o755); err != nil {
		t.Fatal(err)
	}

	// fsnotify needs a beat to dispatch the dir Create + our recursive
	// Add. 100 ms is generous on both kqueue and inotify.
	time.Sleep(120 * time.Millisecond)

	if err := os.WriteFile(filepath.Join(newVault, "note.md"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	ev, ok := rec.waitForEvent(800 * time.Millisecond)
	if !ok {
		t.Fatalf("no event for newly-created vault dir")
	}
	if ev.VaultSlug != "freshvault" {
		t.Fatalf("slug = %q", ev.VaultSlug)
	}
}

func TestManagerCloseIdempotent(t *testing.T) {
	mgr, _, _, _, teardown := newTestManager(t, WithDebounce(20*time.Millisecond))
	teardown() // first close via teardown
	// Idempotent: a second Close must not panic or return an error.
	if err := mgr.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestManagerCloseStopsRunLoop(t *testing.T) {
	mgr, _, _, _, _ := newTestManager(t, WithDebounce(20*time.Millisecond))

	// Close should make Run() return promptly. We call Run() directly
	// to assert it exits, rather than relying on the teardown helper.
	done := make(chan struct{})
	go func() {
		mgr.Run(context.Background())
		close(done)
	}()
	_ = mgr.Close()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("Run did not exit after Close")
	}
}

func TestManagerNoGoroutineLeakOnRapidCycles(t *testing.T) {
	before := runtime.NumGoroutine()

	for i := 0; i < 5; i++ {
		_, _, root, _, teardown := newTestManager(t, WithDebounce(20*time.Millisecond))

		// Trigger an event that schedules a debounce timer; Close
		// must cancel pending timers without leaking the goroutine
		// that AfterFunc would have spawned at fire time.
		_ = os.WriteFile(filepath.Join(root, "vault", "x.md"), []byte("y"), 0o644)
		teardown()
	}

	for i := 0; i < 20; i++ {
		if runtime.NumGoroutine() <= before+2 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	after := runtime.NumGoroutine()
	if after > before+2 {
		t.Fatalf("goroutine leak: before=%d after=%d", before, after)
	}
}

func TestReconcileDirSurfacesExistingFiles(t *testing.T) {
	_, _, root, rec, teardown := newTestManager(t, WithDebounce(20*time.Millisecond))
	defer teardown()

	// Pre-populate a dir BEFORE creating it inside the watched tree so
	// reconcileDir has work to do (mkdir + populate + rename pattern).
	staging := t.TempDir()
	subdir := filepath.Join(staging, "sub")
	if err := os.MkdirAll(subdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subdir, "child.md"), []byte("preload\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Atomic move into the watched tree. fsnotify sees a Create on the
	// directory; reconcileDir must synthesise events for the child.
	dst := filepath.Join(root, "vault", "sub")
	if err := os.Rename(subdir, dst); err != nil {
		t.Fatal(err)
	}

	ev, ok := rec.waitForEvent(800 * time.Millisecond)
	if !ok {
		t.Fatalf("no reconciled event")
	}
	if ev.RelativePath != filepath.ToSlash(filepath.Join("sub", "child.md")) {
		t.Fatalf("relative path = %q", ev.RelativePath)
	}
}
