// Package fswatch is the FS → CRDT bridge for lumi v2 Phase 2.4. It
// watches every vault directory for external markdown edits (TUI's
// $EDITOR, manual Finder saves, Syncthing pulls) and routes them
// through the CRDT registry so live WebSocket subscribers see the
// change.
//
// # Why a debounce + suppression layer is mandatory
//
// fsnotify is a thin shim over inotify/kqueue. Real editors do atomic
// saves: a `:w` in vim or VSCode produces a 4-12 event burst per save
// in a ~20 ms window (CREATE .swp → WRITE → CREATE tmp → WRITE tmp →
// CHMOD → RENAME original → CREATE original → REMOVE .swp). We watch
// the parent directory (never the file — fsnotify drops the watch on
// rename), filter the noise out via an ignore list, and **coalesce
// per-path** through a 100 ms one-shot timer so the handler receives
// a single logical Write per save.
//
// The same handler must NOT fire for writes we initiated ourselves
// (otherwise the CRDT applies its own output back as if it were a
// fresh edit, doubling history and triggering unnecessary broadcasts).
// SkipNext stamps a 750 ms TTL in a suppression map keyed on absolute
// path; the dispatcher drops events whose path is still suppressed.
//
// # Scope of this slice
//
//   - WRITE events on `*.md` files inside a vault → dispatched.
//   - CREATE of new directories → automatically watched + reconciled
//     (synthesised WRITE for files already present, to close the
//     classic fsnotify race).
//   - REMOVE / RENAME of `.md` files → logged but not yet routed to
//     pg.NoteStore.Delete; deferred to a follow-up.
//
// inotify capacity: defaults are 8192 watches / 128 instances per
// user. Bump `fs.inotify.max_user_watches` on the Docker host (NOT
// inside the container — the sysctl lives on the host kernel). One
// `*fsnotify.Watcher` is sufficient until vault count exceeds ~50k
// directories; shard then.
package fswatch

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"

	"github.com/ViniZap4/lumi-server/internal/storage/fs"
)

// Tunables. Defaults are sized to absorb vim's atomic save dance
// without dropping legitimate user edits.
const (
	// DefaultSuppressTTL is how long a SkipNext registration stays
	// effective. Must comfortably exceed the worst-case lag between
	// our write call and the final inotify event for the same
	// (vim+chmod is ~50 ms; 750 ms is 15x headroom).
	DefaultSuppressTTL = 750 * time.Millisecond

	// DefaultDebounce is the per-path coalescing window. 100 ms is
	// the value `watchexec` ships and matches vim's typical save
	// burst length.
	DefaultDebounce = 100 * time.Millisecond

	// JanitorInterval expires entries from the suppression map. Lazy
	// expiry on lookup is good enough for correctness; this just
	// keeps the map from growing unboundedly when no one calls
	// SkipNext for a long time.
	JanitorInterval = 5 * time.Second
)

// Event is the post-debounce, post-filter unit dispatched to the
// handler. Identifies the vault by on-disk slug (first component
// under root) and the note by its vault-relative path (matches
// pg.NoteStore.path).
type Event struct {
	VaultSlug    string
	RelativePath string
	AbsPath      string
}

// Handler receives coalesced external writes. Implementations must be
// safe for concurrent use; the manager calls into them from a single
// goroutine but the user may run other goroutines around them.
type Handler interface {
	HandleFSWrite(ctx context.Context, ev Event)
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(ctx context.Context, ev Event)

// HandleFSWrite implements Handler.
func (f HandlerFunc) HandleFSWrite(ctx context.Context, ev Event) { f(ctx, ev) }

// Manager owns the watcher, suppression registry, and debounce
// scheduler. Construct via New; drive via Run; tear down via Close.
type Manager struct {
	root    string
	fsMgr   *fs.Manager
	log     zerolog.Logger

	handler   Handler
	handlerMu sync.RWMutex

	watcher *fsnotify.Watcher

	suppress    map[string]time.Time
	suppressMu  sync.Mutex
	suppressTTL time.Duration

	debounce   map[string]*time.Timer
	debounceMu sync.Mutex
	debounceFor time.Duration

	rootCtx    context.Context
	rootCancel context.CancelFunc
	closed     atomic.Bool
}

// Option configures the Manager at construction.
type Option func(*Manager)

// WithSuppressTTL overrides DefaultSuppressTTL.
func WithSuppressTTL(d time.Duration) Option {
	return func(m *Manager) { m.suppressTTL = d }
}

// WithDebounce overrides DefaultDebounce.
func WithDebounce(d time.Duration) Option {
	return func(m *Manager) { m.debounceFor = d }
}

// New constructs a Manager rooted at the given absolute path. root
// must exist (caller is responsible for calling fs.Manager.EnsureRootDir
// before this).
//
// handler may be nil at construction time; in that case the caller
// must SetHandler before Run starts dispatching. This lets the
// composition root pass the manager to the notes service (which only
// needs the silencer side) before the WebSocket hub — which the
// handler depends on — is constructed.
func New(root string, fsMgr *fs.Manager, handler Handler, log zerolog.Logger, opts ...Option) (*Manager, error) {
	if root == "" {
		return nil, errors.New("fswatch: root is required")
	}
	if fsMgr == nil {
		return nil, errors.New("fswatch: fs.Manager is required")
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("fswatch: resolve root: %w", err)
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("fswatch: new watcher: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		root:        filepath.Clean(abs),
		fsMgr:       fsMgr,
		handler:     handler,
		log:         log.With().Str("component", "fswatch").Logger(),
		watcher:     w,
		suppress:    make(map[string]time.Time),
		debounce:    make(map[string]*time.Timer),
		suppressTTL: DefaultSuppressTTL,
		debounceFor: DefaultDebounce,
		rootCtx:     ctx,
		rootCancel:  cancel,
	}
	for _, o := range opts {
		o(m)
	}
	return m, nil
}

// Close stops the watcher and cancels any pending debounce timers.
// Idempotent. Returns the watcher's close error if it had one.
func (m *Manager) Close() error {
	if !m.closed.CompareAndSwap(false, true) {
		return nil
	}
	m.rootCancel()

	m.debounceMu.Lock()
	for _, t := range m.debounce {
		t.Stop()
	}
	m.debounce = nil
	m.debounceMu.Unlock()

	return m.watcher.Close()
}

// ---- Watch lifecycle -------------------------------------------------------

// WatchExistingVaults walks the root and adds recursive watches for
// every vault directory it finds. The root itself is also watched so
// new vault directories created out-of-band (e.g. someone copying a
// vault folder in via Finder) are picked up live.
func (m *Manager) WatchExistingVaults() error {
	entries, err := os.ReadDir(m.root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("fswatch: read root: %w", err)
	}
	// Watch the root for top-level dir Creates.
	if err := m.watcher.Add(m.root); err != nil {
		m.log.Warn().Err(err).Str("root", m.root).Msg("watch root failed")
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if err := m.WatchVault(e.Name()); err != nil {
			// Log but keep going — a single bad vault dir should not
			// prevent the others from being watched.
			m.log.Warn().Err(err).Str("slug", e.Name()).Msg("watch vault failed")
		}
	}
	return nil
}

// WatchVault adds recursive watches for the vault identified by slug.
// Safe to call repeatedly; duplicate Adds are no-ops.
func (m *Manager) WatchVault(slug string) error {
	if m.closed.Load() {
		return errors.New("fswatch: manager is closed")
	}
	if slug == "" || strings.ContainsAny(slug, "/\\") {
		return fmt.Errorf("fswatch: invalid slug %q", slug)
	}
	dir := filepath.Join(m.root, slug)
	return m.addRecursive(dir)
}

// addRecursive walks dir and Add()s every directory. Skips the
// `.lumi/` metadata directory (we don't want to receive events for
// CRDT cache files we manage ourselves).
func (m *Manager) addRecursive(dir string) error {
	return filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		if filepath.Base(path) == ".lumi" {
			return filepath.SkipDir
		}
		if err := m.watcher.Add(path); err != nil {
			return fmt.Errorf("watcher.Add(%s): %w", path, err)
		}
		return nil
	})
}

// ---- Self-write suppression ------------------------------------------------

// SkipNext registers absPath in the suppression map for SuppressTTL.
// Events for that path arriving within the window are dropped. Lumi's
// own writes (notes.Service.Create, Update body, ApplyDiff, Delete,
// Move) must call this immediately BEFORE invoking fs.Manager.
func (m *Manager) SkipNext(absPath string) {
	if absPath == "" {
		return
	}
	m.suppressMu.Lock()
	m.suppress[absPath] = time.Now().Add(m.suppressTTL)
	m.suppressMu.Unlock()
}

// shouldSuppress returns true if absPath is currently within a
// SkipNext window. Lazily expires stale entries.
func (m *Manager) shouldSuppress(absPath string) bool {
	now := time.Now()
	m.suppressMu.Lock()
	defer m.suppressMu.Unlock()
	exp, ok := m.suppress[absPath]
	if !ok {
		return false
	}
	if now.After(exp) {
		delete(m.suppress, absPath)
		return false
	}
	return true
}

// ---- Run loop --------------------------------------------------------------

// Run blocks reading from the watcher's Events / Errors channels and
// the janitor tick. Returns when ctx is cancelled or Close is called.
// Typically launched as `go mgr.Run(ctx)`.
func (m *Manager) Run(ctx context.Context) {
	janitor := time.NewTicker(JanitorInterval)
	defer janitor.Stop()

	for {
		select {
		case ev, ok := <-m.watcher.Events:
			if !ok {
				return
			}
			m.dispatch(ev)
		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			m.log.Warn().Err(err).Msg("watcher error")
		case <-janitor.C:
			m.expireSuppress()
		case <-ctx.Done():
			return
		case <-m.rootCtx.Done():
			return
		}
	}
}

func (m *Manager) expireSuppress() {
	now := time.Now()
	m.suppressMu.Lock()
	for p, exp := range m.suppress {
		if now.After(exp) {
			delete(m.suppress, p)
		}
	}
	m.suppressMu.Unlock()
}

// dispatch is the per-event filter and debouncer.
func (m *Manager) dispatch(ev fsnotify.Event) {
	// Directory create: watch it + reconcile.
	if ev.Op.Has(fsnotify.Create) {
		if info, err := os.Stat(ev.Name); err == nil && info.IsDir() {
			if filepath.Base(ev.Name) != ".lumi" {
				if err := m.addRecursive(ev.Name); err != nil {
					m.log.Warn().Err(err).Str("dir", ev.Name).Msg("recursive add failed")
				}
				m.reconcileDir(ev.Name)
			}
			return
		}
	}

	// We only care about content changes on regular files.
	if !(ev.Op.Has(fsnotify.Write) || ev.Op.Has(fsnotify.Create) || ev.Op.Has(fsnotify.Rename)) {
		return
	}
	if !isInterestingPath(ev.Name) {
		return
	}
	if m.shouldSuppress(ev.Name) {
		return
	}

	m.debounceMu.Lock()
	if t, ok := m.debounce[ev.Name]; ok {
		t.Reset(m.debounceFor)
		m.debounceMu.Unlock()
		return
	}
	path := ev.Name // pin for the closure
	m.debounce[path] = time.AfterFunc(m.debounceFor, func() {
		m.debounceMu.Lock()
		delete(m.debounce, path)
		m.debounceMu.Unlock()
		m.fire(path)
	})
	m.debounceMu.Unlock()
}

// reconcileDir synthesises Write events for every existing `.md` file
// inside dir so the caller sees them as fresh writes. Closes the
// fsnotify race where a directory is created and populated before our
// Add() lands.
func (m *Manager) reconcileDir(dir string) {
	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // best-effort
		}
		if d.IsDir() {
			if filepath.Base(path) == ".lumi" && path != dir {
				return filepath.SkipDir
			}
			return nil
		}
		if !isInterestingPath(path) {
			return nil
		}
		// Use the debounce path so reconciled writes coalesce with any
		// genuine events arriving moments later.
		m.dispatch(fsnotify.Event{Name: path, Op: fsnotify.Write})
		return nil
	})
}

// SetHandler installs the dispatch target. Safe to call at runtime;
// the manager guards with a RW mutex so a swap during Run is race-free.
func (m *Manager) SetHandler(h Handler) {
	m.handlerMu.Lock()
	m.handler = h
	m.handlerMu.Unlock()
}

// fire stat-checks the path (in case the file was deleted in the
// debounce window) and invokes the handler.
func (m *Manager) fire(absPath string) {
	if m.shouldSuppress(absPath) {
		return
	}
	info, err := os.Stat(absPath)
	if err != nil || info.IsDir() {
		return
	}
	rel, err := filepath.Rel(m.root, absPath)
	if err != nil {
		return
	}
	parts := strings.SplitN(filepath.ToSlash(rel), "/", 2)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return
	}
	ev := Event{
		VaultSlug:    parts[0],
		RelativePath: parts[1],
		AbsPath:      absPath,
	}
	m.handlerMu.RLock()
	h := m.handler
	m.handlerMu.RUnlock()
	if h == nil {
		return
	}
	h.HandleFSWrite(m.rootCtx, ev)
}

// ---- Helpers ---------------------------------------------------------------

// isInterestingPath returns true iff absPath looks like a real
// markdown file under a vault. Editor temp files, dotfiles, and
// non-`.md` extensions are excluded.
func isInterestingPath(absPath string) bool {
	base := filepath.Base(absPath)
	if base == "" {
		return false
	}
	if strings.HasPrefix(base, ".") {
		return false
	}
	// Editor scratch / atomic-save artefacts.
	if base == "4913" || strings.HasSuffix(base, "~") || strings.HasSuffix(base, ".swp") || strings.HasSuffix(base, ".swo") || strings.HasSuffix(base, ".tmp") {
		return false
	}
	if !strings.HasSuffix(strings.ToLower(base), ".md") {
		return false
	}
	// Anything under a `.lumi/` directory inside the path is metadata.
	if strings.Contains(absPath, string(os.PathSeparator)+".lumi"+string(os.PathSeparator)) {
		return false
	}
	return true
}
