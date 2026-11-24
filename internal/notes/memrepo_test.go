package notes

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/storage/pg"
)

// fakeNoteRepo is an in-memory NoteRepo with the store's seq semantics:
// one mutex plays the role of the vault_heads row lock, so every write
// takes the next seq and commits atomically with it.
type fakeNoteRepo struct {
	mu      sync.Mutex
	byVault map[uuid.UUID][]domain.Note
	heads   map[uuid.UUID]int64
	floors  map[uuid.UUID]int64
	tombs   map[uuid.UUID][]domain.NoteTombstone
	// onDelete, when set, plays the FK cascade from notes to the CRDT
	// tables (called after the row is gone, outside the repo lock).
	onDelete func(vaultID uuid.UUID, id string)
}

func (f *fakeNoteRepo) bumpLocked(vaultID uuid.UUID) int64 {
	if f.heads == nil {
		f.heads = map[uuid.UUID]int64{}
	}
	f.heads[vaultID]++
	return f.heads[vaultID]
}

func (f *fakeNoteRepo) Upsert(_ context.Context, n domain.Note) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	seq := f.bumpLocked(n.VaultID)
	n.ChangeSeq = seq
	rows := f.byVault[n.VaultID]
	for i := range rows {
		if rows[i].ID == n.ID {
			n.CreatedAt = rows[i].CreatedAt
			// Like the pg store: an update never touches crdt_epoch.
			n.CRDTEpoch = rows[i].CRDTEpoch
			rows[i] = n
			return seq, nil
		}
	}
	if n.CRDTEpoch == "" {
		n.CRDTEpoch = domain.NewCRDTEpoch()
	}
	f.byVault[n.VaultID] = append(rows, n)
	return seq, nil
}

func (f *fakeNoteRepo) SetCreatedAt(_ context.Context, vaultID uuid.UUID, id string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, n := range f.byVault[vaultID] {
		if n.ID == id {
			f.byVault[vaultID][i].CreatedAt = at
			return nil
		}
	}
	return domain.ErrNotFound
}

// setEpoch mirrors pg.NoteYjsStore.SeedSnapshot's notes-row half: stamp
// epoch, bumping the seq only when it changes.
func (f *fakeNoteRepo) setEpoch(vaultID uuid.UUID, id, epoch string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rows := f.byVault[vaultID]
	for i := range rows {
		if rows[i].ID == id {
			if rows[i].CRDTEpoch == epoch {
				return 0, nil
			}
			seq := f.bumpLocked(vaultID)
			rows[i].CRDTEpoch = epoch
			rows[i].ChangeSeq = seq
			return seq, nil
		}
	}
	return 0, domain.ErrNotFound
}

func (f *fakeNoteRepo) TouchContent(_ context.Context, vaultID uuid.UUID, id string, at time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rows := f.byVault[vaultID]
	for i := range rows {
		if rows[i].ID == id {
			seq := f.bumpLocked(vaultID)
			rows[i].ChangeSeq = seq
			rows[i].UpdatedAt = at
			return seq, nil
		}
	}
	return 0, domain.ErrNotFound
}

func (f *fakeNoteRepo) Get(_ context.Context, vaultID uuid.UUID, id string) (domain.Note, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range f.byVault[vaultID] {
		if n.ID == id {
			return n, nil
		}
	}
	return domain.Note{}, domain.ErrNotFound
}

func (f *fakeNoteRepo) GetByPath(_ context.Context, vaultID uuid.UUID, path string) (domain.Note, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, n := range f.byVault[vaultID] {
		if n.Path == path {
			return n, nil
		}
	}
	return domain.Note{}, domain.ErrNotFound
}

func (f *fakeNoteRepo) ListForVault(_ context.Context, vaultID uuid.UUID, limit, offset int) ([]domain.Note, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	all := f.byVault[vaultID]
	if offset >= len(all) {
		return nil, nil
	}
	end := offset + limit
	if end > len(all) {
		end = len(all)
	}
	return append([]domain.Note(nil), all[offset:end]...), nil
}

func (f *fakeNoteRepo) Delete(ctx context.Context, vaultID uuid.UUID, id string) (int64, error) {
	seq, err := f.deleteRow(ctx, vaultID, id)
	if err == nil && f.onDelete != nil {
		f.onDelete(vaultID, id)
	}
	return seq, err
}

func (f *fakeNoteRepo) deleteRow(_ context.Context, vaultID uuid.UUID, id string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rows := f.byVault[vaultID]
	for i := range rows {
		if rows[i].ID == id {
			seq := f.bumpLocked(vaultID)
			f.byVault[vaultID] = append(rows[:i:i], rows[i+1:]...)
			if f.tombs == nil {
				f.tombs = map[uuid.UUID][]domain.NoteTombstone{}
			}
			f.tombs[vaultID] = append(f.tombs[vaultID], domain.NoteTombstone{ID: id, Seq: seq})
			return seq, nil
		}
	}
	return 0, domain.ErrNotFound
}

// prune drops tombstones with seq <= upTo and raises the floor.
func (f *fakeNoteRepo) prune(vaultID uuid.UUID, upTo int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var keep []domain.NoteTombstone
	for _, t := range f.tombs[vaultID] {
		if t.Seq > upTo {
			keep = append(keep, t)
		}
	}
	f.tombs[vaultID] = keep
	if f.floors == nil {
		f.floors = map[uuid.UUID]int64{}
	}
	f.floors[vaultID] = upTo
}

func (f *fakeNoteRepo) Changes(_ context.Context, vaultID uuid.UUID, after int64, limit int) (domain.NoteChanges, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	head := f.heads[vaultID]
	if after > 0 && after < f.floors[vaultID] {
		return domain.NoteChanges{}, &domain.ResyncRequiredError{Head: head}
	}
	var ns []domain.Note
	for _, n := range f.byVault[vaultID] {
		if n.ChangeSeq > after && n.ChangeSeq <= head {
			ns = append(ns, n)
		}
	}
	sort.Slice(ns, func(i, j int) bool { return ns[i].ChangeSeq < ns[j].ChangeSeq })
	var ts []domain.NoteTombstone
	for _, t := range f.tombs[vaultID] {
		if t.Seq > after && t.Seq <= head {
			ts = append(ts, t)
		}
	}
	out := domain.NoteChanges{Head: head}
	out.Notes, out.Deleted, out.More = pg.MergeChangePage(ns, ts, limit)
	return out, nil
}
