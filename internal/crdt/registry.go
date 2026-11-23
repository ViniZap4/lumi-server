package crdt

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"sync"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// Compaction thresholds. The update log is folded into a new snapshot
// when either limit is exceeded. Values come from SPEC.md "Persistence"
// (200 entries / ~1 MiB). Tune as needed once we have telemetry.
const (
	CompactCountThreshold = 200
	CompactBytesThreshold = 1 << 20 // 1 MiB
)

// SnapshotRepo is the storage boundary the registry depends on. The pg
// note_yjs store satisfies it.
type SnapshotRepo interface {
	GetSnapshot(ctx context.Context, vaultID uuid.UUID, noteID string) (SnapshotRow, error)
	UpsertSnapshot(ctx context.Context, vaultID uuid.UUID, noteID string, state []byte) error
	// SeedSnapshot starts a new CRDT history atomically: replace the
	// snapshot with state, drop every update-log row and stamp epoch on
	// the note's metadata. Returns the vault seq bumped for the epoch
	// change, 0 when the stored epoch already equalled epoch.
	SeedSnapshot(ctx context.Context, vaultID uuid.UUID, noteID string, state []byte, epoch string) (int64, error)

	AppendUpdate(ctx context.Context, vaultID uuid.UUID, noteID string,
		update []byte, originUserID uuid.UUID, originKind string) (int64, error)
	ListUpdatesSince(ctx context.Context, vaultID uuid.UUID, noteID string,
		sinceID int64, limit int) ([]UpdateRow, error)
	CountUpdates(ctx context.Context, vaultID uuid.UUID, noteID string) (count int, bytes int64, err error)
	DeleteUpdatesUpTo(ctx context.Context, vaultID uuid.UUID, noteID string, maxID int64) (int64, error)
	HighestUpdateID(ctx context.Context, vaultID uuid.UUID, noteID string) (int64, error)
}

// SnapshotRow is the storage-layer DTO for a snapshot row. Mirrors
// pg.NoteYjsSnapshot but lives in this package so callers do not need
// to depend on the storage package directly.
type SnapshotRow struct {
	State []byte
}

// UpdateRow is the storage-layer DTO for an update log row.
type UpdateRow struct {
	ID         int64
	Update     []byte
	OriginKind string
}

// Registry orchestrates snapshot + update-log persistence around a yrs
// document. It holds no in-memory document cache: the authoritative
// in-memory doc for a note is owned by the wsync.Hub room, and every
// mutation must go through it (see wsync.Hub.ApplyUpdate / ApplyText).
// Direct LoadDoc + PersistChange is only safe where no Hub exists.
type Registry struct {
	store SnapshotRepo

	hookMu     sync.RWMutex
	onPersist  PersistHook
	onEpoch    EpochHook
	initSource InitSource

	seedLocks [64]sync.Mutex
}

// PersistHook observes every successfully-appended update (v3 F2: the
// federation relay fans updates out to peer servers from here — the one
// choke point every write path crosses: live WS, REST diff, FS watcher,
// and inbound federation itself). Implementations MUST be fast and
// non-blocking; they run synchronously on the write path.
type PersistHook func(vaultID uuid.UUID, noteID string, update []byte, originKind string)

// EpochHook observes a CRDT epoch rotation committed by a seed (lazy
// init, InitFromText with a new epoch). seq is the vault seq the rotation
// was stamped with (> 0). Must be fast and non-blocking.
type EpochHook func(vaultID uuid.UUID, noteID, epoch string, seq int64)

// SetOnEpochChange installs the epoch-rotation hook. Pass nil to remove.
func (r *Registry) SetOnEpochChange(h EpochHook) {
	r.hookMu.Lock()
	defer r.hookMu.Unlock()
	r.onEpoch = h
}

func (r *Registry) fireEpochHook(vaultID uuid.UUID, noteID, epoch string, seq int64) {
	r.hookMu.RLock()
	h := r.onEpoch
	r.hookMu.RUnlock()
	if h != nil && seq > 0 {
		h(vaultID, noteID, epoch, seq)
	}
}

// NewRegistry constructs a Registry around the storage. store must not
// be nil.
func NewRegistry(store SnapshotRepo) *Registry {
	if store == nil {
		panic("crdt.NewRegistry: store is required")
	}
	return &Registry{store: store}
}

// SetOnPersist installs the persist hook. Pass nil to remove.
func (r *Registry) SetOnPersist(h PersistHook) {
	r.hookMu.Lock()
	defer r.hookMu.Unlock()
	r.onPersist = h
}

func (r *Registry) firePersistHook(vaultID uuid.UUID, noteID string, update []byte, originKind string) {
	r.hookMu.RLock()
	h := r.onPersist
	r.hookMu.RUnlock()
	if h != nil {
		h(vaultID, noteID, update, originKind)
	}
}

// InitSource returns the on-disk body of an existing note so the registry
// can seed a CRDT document that has never been initialised (legacy notes,
// notes whose create-time seeding failed). It must return ("", nil) when
// the note has no body on disk yet (e.g. a federation replica waiting for
// its first mirrored update) and a non-nil error only for real failures.
type InitSource func(ctx context.Context, vaultID uuid.UUID, noteID string) (string, error)

// SetInitSource installs the lazy-init body source. nil disables lazy
// initialisation (LoadDoc then returns an empty doc for unknown notes).
//
// Single-seeder invariant (CRDT client protocol §10 S5): only the server
// that is home for a note may seed it from text. Federation replicas
// receive the home's state instead; their notes never reach lazy init
// with a non-empty body because the file only lands on disk through the
// mirror of that state.
func (r *Registry) SetInitSource(fn InitSource) {
	r.hookMu.Lock()
	defer r.hookMu.Unlock()
	r.initSource = fn
}

func (r *Registry) getInitSource() InitSource {
	r.hookMu.RLock()
	defer r.hookMu.RUnlock()
	return r.initSource
}

// noteLock returns the striped mutex serialising seeding for a note, so
// two concurrent first loads cannot each insert the body under their own
// clientID (which would merge as a duplicated body, vector V2).
func (r *Registry) noteLock(vaultID uuid.UUID, noteID string) *sync.Mutex {
	h := fnv.New32a()
	_, _ = h.Write(vaultID[:])
	_, _ = h.Write([]byte(noteID))
	return &r.seedLocks[h.Sum32()%uint32(len(r.seedLocks))]
}

// LoadDoc fetches the persisted snapshot (if any) plus every update in
// the log and returns a freshly-allocated yrs document reflecting their
// merged state. The caller owns Close().
//
// "Every update in the log" is correct rather than "every update since
// the snapshot": Yjs CRDT merges are idempotent, so feeding the doc an
// update it has already absorbed is a no-op. Avoiding the bookkeeping
// keeps the storage schema simple.
//
// When neither a snapshot nor any update exists and an InitSource is
// installed, the document is seeded from the note's on-disk body and the
// seed is stored as the snapshot (lazy init, protocol §10 S4).
func (r *Registry) LoadDoc(ctx context.Context, vaultID uuid.UUID, noteID string) (*Doc, error) {
	doc, empty, err := r.loadPersisted(ctx, vaultID, noteID)
	if err != nil || !empty {
		return doc, err
	}
	src := r.getInitSource()
	if src == nil {
		return doc, nil
	}
	_ = doc.Close()

	mu := r.noteLock(vaultID, noteID)
	mu.Lock()
	defer mu.Unlock()
	// Re-check under the lock: a concurrent loader may have seeded.
	doc, empty, err = r.loadPersisted(ctx, vaultID, noteID)
	if err != nil || !empty {
		return doc, err
	}
	body, err := src(ctx, vaultID, noteID)
	if err != nil {
		_ = doc.Close()
		return nil, fmt.Errorf("crdt registry: lazy init read body: %w", err)
	}
	if body == "" {
		return doc, nil
	}
	_ = doc.Close()
	// Lazy init starts a new history: a fresh epoch, so a client replica
	// tagged with the note's previous epoch is never merged into it.
	seeded, _, err := r.seed(ctx, vaultID, noteID, body, "lazy-init", "")
	if err != nil {
		return nil, err
	}
	return seeded, nil
}

// loadPersisted rebuilds the doc from snapshot + log. empty reports that
// nothing at all is persisted for the note.
func (r *Registry) loadPersisted(ctx context.Context, vaultID uuid.UUID, noteID string) (*Doc, bool, error) {
	var initial []byte
	haveSnap := false
	snap, err := r.store.GetSnapshot(ctx, vaultID, noteID)
	switch {
	case err == nil:
		initial = snap.State
		haveSnap = true
	case errors.Is(err, domain.ErrNotFound):
	default:
		// A transient storage error must not masquerade as "no state":
		// the caller would then seed or edit an empty doc and the next
		// mirror would overwrite the file.
		return nil, false, fmt.Errorf("crdt registry: get snapshot: %w", err)
	}

	doc, err := LoadDoc(initial)
	if err != nil {
		return nil, false, fmt.Errorf("crdt registry: load snapshot: %w", err)
	}

	updates, err := r.store.ListUpdatesSince(ctx, vaultID, noteID, 0, 0)
	if err != nil {
		_ = doc.Close()
		return nil, false, fmt.Errorf("crdt registry: list updates: %w", err)
	}
	for _, u := range updates {
		if err := doc.ApplyUpdate(u.Update); err != nil {
			_ = doc.Close()
			return nil, false, fmt.Errorf("crdt registry: replay update %d: %w", u.ID, err)
		}
	}
	return doc, !haveSnap && len(updates) == 0, nil
}

// PersistChange appends an update produced by a transaction on doc, then
// runs compaction if the log has grown past either threshold. doc must
// already reflect the change captured in update — typically you get
// `update` from doc.ApplyTextDiff and pass the same doc straight in.
//
// originUserID may be uuid.Nil for system-initiated writes.
func (r *Registry) PersistChange(
	ctx context.Context,
	vaultID uuid.UUID, noteID string,
	update []byte, originUserID uuid.UUID, originKind string,
	doc *Doc,
) error {
	if len(update) == 0 {
		return nil
	}
	if _, err := r.store.AppendUpdate(ctx, vaultID, noteID, update, originUserID, originKind); err != nil {
		return err
	}
	r.firePersistHook(vaultID, noteID, update, originKind)

	count, bytes, err := r.store.CountUpdates(ctx, vaultID, noteID)
	if err != nil {
		// Append succeeded; failure to *check* size shouldn't fail the
		// request. Compaction will catch up on the next write.
		return nil
	}
	if count < CompactCountThreshold && bytes < CompactBytesThreshold {
		return nil
	}
	return r.compact(ctx, vaultID, noteID, doc)
}

// InitFromText seeds a brand-new note's CRDT: a fresh doc holding body
// is stored as the snapshot and a fresh epoch is stamped on the note.
// Equivalent to InitFromTextEpoch with epoch "".
func (r *Registry) InitFromText(
	ctx context.Context,
	vaultID uuid.UUID, noteID string,
	body string,
	originUserID uuid.UUID, originKind string,
) error {
	_, err := r.InitFromTextEpoch(ctx, vaultID, noteID, body, "", originUserID, originKind)
	return err
}

// InitFromTextEpoch creates a fresh doc, applies `body` as the initial
// text, and stores the resulting state as the snapshot, starting a new
// CRDT history tagged epoch (a fresh one when ""). Use during note
// create (and vault copy, on the home server only) to seed the CRDT so
// subsequent updates have a base state. Callers that inserted the note
// row with an epoch pass that epoch so the seed does not rotate it again.
//
// Seeding is exactly-once per history: when state is already persisted
// for the note (a concurrent first load lazily seeded it from the same
// freshly written file), nothing is replaced and ("", nil) is returned;
// the note row then carries the epoch that seed stamped. Otherwise the
// epoch written is returned.
//
// originUserID may be uuid.Nil; originKind is typically
// "snapshot-init".
func (r *Registry) InitFromTextEpoch(
	ctx context.Context,
	vaultID uuid.UUID, noteID string,
	body, epoch string,
	originUserID uuid.UUID, originKind string,
) (string, error) {
	_ = originUserID
	mu := r.noteLock(vaultID, noteID)
	mu.Lock()
	defer mu.Unlock()
	existing, empty, err := r.loadPersisted(ctx, vaultID, noteID)
	if err != nil {
		return "", err
	}
	_ = existing.Close()
	if !empty {
		return "", nil
	}
	doc, written, err := r.seed(ctx, vaultID, noteID, body, originKind, epoch)
	if err != nil {
		return "", err
	}
	_ = doc.Close()
	return written, nil
}

// seed builds a doc holding body and stores it as the snapshot of a new
// CRDT history tagged epoch (fresh when ""), atomically with the epoch
// and the removal of any stale update-log rows. No log row is appended:
// the snapshot is the full base state. Caller holds the note's seed lock
// and owns the returned doc.
func (r *Registry) seed(ctx context.Context, vaultID uuid.UUID, noteID, body, originKind, epoch string) (*Doc, string, error) {
	if epoch == "" {
		epoch = domain.NewCRDTEpoch()
	}
	doc := NewDoc()
	if body != "" {
		if _, err := doc.ApplyTextDiff(body, originKind); err != nil {
			_ = doc.Close()
			return nil, "", fmt.Errorf("crdt registry: seed text: %w", err)
		}
	}
	state, err := doc.EncodeStateAsUpdate()
	if err != nil {
		_ = doc.Close()
		return nil, "", fmt.Errorf("crdt registry: encode initial state: %w", err)
	}
	seq, err := r.store.SeedSnapshot(ctx, vaultID, noteID, state, epoch)
	if err != nil {
		_ = doc.Close()
		return nil, "", err
	}
	r.fireEpochHook(vaultID, noteID, epoch, seq)
	return doc, epoch, nil
}

// compact captures the current doc state as a new snapshot and deletes
// every update with id <= maxID where maxID is the highest log entry at
// the moment we read it. Updates written concurrently after that read
// survive — they reference state already absorbed by the snapshot, so
// re-applying them on the next load is a CRDT no-op.
func (r *Registry) compact(ctx context.Context, vaultID uuid.UUID, noteID string, doc *Doc) error {
	maxID, err := r.store.HighestUpdateID(ctx, vaultID, noteID)
	if err != nil {
		return fmt.Errorf("crdt compact: max id: %w", err)
	}
	state, err := doc.EncodeStateAsUpdate()
	if err != nil {
		return fmt.Errorf("crdt compact: encode state: %w", err)
	}
	if err := r.store.UpsertSnapshot(ctx, vaultID, noteID, state); err != nil {
		return fmt.Errorf("crdt compact: write snapshot: %w", err)
	}
	if _, err := r.store.DeleteUpdatesUpTo(ctx, vaultID, noteID, maxID); err != nil {
		return fmt.Errorf("crdt compact: delete updates: %w", err)
	}
	return nil
}
