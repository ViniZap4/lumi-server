package crdt

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
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
// document. Phase 2.2 ships without an in-memory document cache: each
// public method loads the doc, performs work, closes the doc. Slice 2.3
// (live Yjs sync) introduces an LRU keyed by (vault_id, note_id).
type Registry struct {
	store SnapshotRepo

	hookMu    sync.RWMutex
	onPersist PersistHook
}

// PersistHook observes every successfully-appended update (v3 F2: the
// federation relay fans updates out to peer servers from here — the one
// choke point every write path crosses: live WS, REST diff, FS watcher,
// and inbound federation itself). Implementations MUST be fast and
// non-blocking; they run synchronously on the write path.
type PersistHook func(vaultID uuid.UUID, noteID string, update []byte, originKind string)

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

// LoadDoc fetches the persisted snapshot (if any) plus every update in
// the log and returns a freshly-allocated yrs document reflecting their
// merged state. The caller owns Close().
//
// "Every update in the log" is correct rather than "every update since
// the snapshot": Yjs CRDT merges are idempotent, so feeding the doc an
// update it has already absorbed is a no-op. Avoiding the bookkeeping
// keeps the storage schema simple.
func (r *Registry) LoadDoc(ctx context.Context, vaultID uuid.UUID, noteID string) (*Doc, error) {
	var initial []byte
	snap, err := r.store.GetSnapshot(ctx, vaultID, noteID)
	if err == nil {
		initial = snap.State
	}

	doc, err := LoadDoc(initial)
	if err != nil {
		return nil, fmt.Errorf("crdt registry: load snapshot: %w", err)
	}

	updates, err := r.store.ListUpdatesSince(ctx, vaultID, noteID, 0, 0)
	if err != nil {
		_ = doc.Close()
		return nil, fmt.Errorf("crdt registry: list updates: %w", err)
	}
	for _, u := range updates {
		if err := doc.ApplyUpdate(u.Update); err != nil {
			_ = doc.Close()
			return nil, fmt.Errorf("crdt registry: replay update %d: %w", u.ID, err)
		}
	}
	return doc, nil
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

// InitFromText creates a fresh doc, applies `body` as the initial text,
// stores the resulting state as a snapshot, and persists the single
// generative update against an empty document. Use during note create
// to seed the CRDT log so subsequent diff updates have a base state.
//
// originUserID may be uuid.Nil; originKind is typically
// "snapshot-init".
func (r *Registry) InitFromText(
	ctx context.Context,
	vaultID uuid.UUID, noteID string,
	body string,
	originUserID uuid.UUID, originKind string,
) error {
	doc := NewDoc()
	defer doc.Close()
	if body != "" {
		if _, err := doc.ApplyTextDiff(body, originKind); err != nil {
			return fmt.Errorf("crdt registry: seed text: %w", err)
		}
	}
	state, err := doc.EncodeStateAsUpdate()
	if err != nil {
		return fmt.Errorf("crdt registry: encode initial state: %w", err)
	}
	if err := r.store.UpsertSnapshot(ctx, vaultID, noteID, state); err != nil {
		return err
	}
	// We do not append an entry to the update log: the snapshot now is
	// the full base state. Subsequent diffs (web, tui-diff) will append
	// against it.
	return nil
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
