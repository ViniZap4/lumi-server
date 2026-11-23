package notes

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/capguard"
	"github.com/ViniZap4/lumi-server/internal/crdt"
	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/wsync"
)

// CRDT lineage contract (protocol §12): crdt_epoch changes exactly when a
// new CRDT history starts for a note id.

func (f *crdtFixture) row(t *testing.T, id string) domain.Note {
	t.Helper()
	n, err := f.yjs.notes.Get(context.Background(), f.vault.ID, id)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestEpoch_CreateStampsOneEpochEverywhere(t *testing.T) {
	f := newCRDTFixture(t)
	ctx := context.Background()
	n, err := f.svc.Create(ctx, f.vault.ID, CreateInput{Title: "Note", Body: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	if len(n.CRDTEpoch) != 32 || f.row(t, n.ID).CRDTEpoch != n.CRDTEpoch {
		t.Fatalf("create epoch %q, row %q", n.CRDTEpoch, f.row(t, n.ID).CRDTEpoch)
	}
	snap, err := f.svc.GetSnapshot(ctx, f.vault.ID, n.ID)
	if err != nil || snap.CRDTEpoch != n.CRDTEpoch {
		t.Fatalf("snapshot epoch %q err %v, want %q", snap.CRDTEpoch, err, n.CRDTEpoch)
	}
	sv, err := f.svc.GetStateVector(ctx, f.vault.ID, n.ID)
	if err != nil || sv.CRDTEpoch != n.CRDTEpoch || !bytes.Equal(sv.StateVector, snap.VectorClock) {
		t.Fatalf("state-vector %+v err %v, want epoch %q sv %x", sv, err, n.CRDTEpoch, snap.VectorClock)
	}
}

// Delete + recreate under the same id: new epoch, and the old history's
// live room is gone — its sockets get 4404, its pending mirror never
// lands on the new note's file, and new joiners see only the new seed.
func TestEpoch_DeleteRecreateRotatesAndDropsLiveRoom(t *testing.T) {
	f := newCRDTFixture(t)
	ctx := context.Background()
	old, err := f.svc.Create(ctx, f.vault.ID, CreateInput{Title: "Note", Body: "old body"})
	if err != nil {
		t.Fatal(err)
	}
	web := f.hub.NewSubscriber(uuid.New())
	room, err := f.hub.Join(ctx, f.vault.ID, old.ID, web)
	if err != nil {
		t.Fatal(err)
	}
	liveEdit(t, room, web, "old body, edited live") // schedules the debounced mirror

	if err := f.svc.Delete(ctx, f.vault.ID, old.ID, uuid.Nil, "", ""); err != nil {
		t.Fatal(err)
	}
	select {
	case <-web.Done:
	case <-time.After(time.Second):
		t.Fatal("live socket not closed on delete")
	}
	if code, _ := web.CloseCode(); code != wsync.CloseNotFound {
		t.Fatalf("close code %d, want 4404", code)
	}
	f.hub.Leave(room, web)

	fresh, err := f.svc.Create(ctx, f.vault.ID, CreateInput{Title: "Note", Body: "new body"})
	if err != nil {
		t.Fatal(err)
	}
	if fresh.ID != old.ID {
		t.Fatalf("recreate got id %q, want %q", fresh.ID, old.ID)
	}
	if fresh.CRDTEpoch == "" || fresh.CRDTEpoch == old.CRDTEpoch {
		t.Fatalf("recreate epoch %q, old %q: must differ", fresh.CRDTEpoch, old.CRDTEpoch)
	}
	time.Sleep(80 * time.Millisecond) // past the old room's mirror debounce
	if got := f.diskBody(t, fresh); got != "new body" {
		t.Fatalf("disk = %q: the deleted note's room mirrored onto the new note", got)
	}
	snap, err := f.svc.GetSnapshot(ctx, f.vault.ID, fresh.ID)
	if err != nil || snap.Text != "new body" || snap.CRDTEpoch != fresh.CRDTEpoch {
		t.Fatalf("snapshot %q epoch %q err %v", snap.Text, snap.CRDTEpoch, err)
	}
}

// Lazy init (seeding a never-initialised note from its file) rotates the
// epoch, bumps the vault seq and publishes it; reads report the epoch of
// the seeded history, not the stale pre-seed one.
func TestEpoch_LazyInitFromFileRotates(t *testing.T) {
	f := newCRDTFixture(t)
	heads := &headRec{}
	f.svc.SetHeadPublisher(heads)
	f.reg.SetOnEpochChange(f.svc.EpochRotated)
	ctx := context.Background()
	n, err := f.svc.Create(ctx, f.vault.ID, CreateInput{Title: "Legacy", Body: "from disk"})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a legacy note: no CRDT state at all.
	f.yjs.mu.Lock()
	delete(f.yjs.snaps, yk(f.vault.ID, n.ID))
	f.yjs.mu.Unlock()
	seqBefore := f.row(t, n.ID).ChangeSeq

	snap, err := f.svc.GetSnapshot(ctx, f.vault.ID, n.ID)
	if err != nil {
		t.Fatal(err)
	}
	row := f.row(t, n.ID)
	if snap.Text != "from disk" || snap.CRDTEpoch == n.CRDTEpoch || snap.CRDTEpoch != row.CRDTEpoch {
		t.Fatalf("snapshot %q epoch %q (create %q, row %q)", snap.Text, snap.CRDTEpoch, n.CRDTEpoch, row.CRDTEpoch)
	}
	if row.ChangeSeq <= seqBefore {
		t.Fatalf("lazy init did not bump the seq (%d → %d)", seqBefore, row.ChangeSeq)
	}
	if hs := heads.of(f.vault.ID); len(hs) == 0 || hs[len(hs)-1] != row.ChangeSeq {
		t.Fatalf("published heads %v, want last %d", hs, row.ChangeSeq)
	}
	again, _ := f.svc.GetStateVector(ctx, f.vault.ID, n.ID)
	if again.CRDTEpoch != row.CRDTEpoch {
		t.Fatalf("second read rotated again: %q", again.CRDTEpoch)
	}
}

// Everything that continues the same history keeps the epoch: live
// edits, the fs-watcher diff merge, PATCH body, raw updates, 3-way /diff,
// moves, and compaction.
func TestEpoch_EditsFSMergeMoveAndCompactionKeepEpoch(t *testing.T) {
	f := newCRDTFixture(t)
	ctx := context.Background()
	n, err := f.svc.Create(ctx, f.vault.ID, CreateInput{Title: "Keep", Body: "base"})
	if err != nil {
		t.Fatal(err)
	}
	epoch := n.CRDTEpoch
	check := func(step string) {
		t.Helper()
		if got := f.row(t, n.ID).CRDTEpoch; got != epoch {
			t.Fatalf("%s changed the epoch: %q → %q", step, epoch, got)
		}
		sv, err := f.svc.GetStateVector(ctx, f.vault.ID, n.ID)
		if err != nil || sv.CRDTEpoch != epoch {
			t.Fatalf("%s: state-vector epoch %q err %v", step, sv.CRDTEpoch, err)
		}
	}

	web := f.hub.NewSubscriber(uuid.New())
	room, err := f.hub.Join(ctx, f.vault.ID, n.ID, web)
	if err != nil {
		t.Fatal(err)
	}
	liveEdit(t, room, web, "base live")
	check("live edit")

	// External editor rewrote the file; the watcher diff-merges it.
	if _, err := f.hub.ApplyText(ctx, f.vault.ID, n.ID, "base live + external", nil,
		wsync.ApplyOptions{Origin: wsync.OriginFSWatcher, Mirror: wsync.MirrorNone}); err != nil {
		t.Fatal(err)
	}
	check("fs-watcher merge")

	body := "patched"
	if _, err := f.svc.Update(ctx, f.vault.ID, n.ID, UpdateInput{Body: &body}); err != nil {
		t.Fatal(err)
	}
	check("PATCH body")

	snap, _ := f.svc.GetSnapshot(ctx, f.vault.ID, n.ID)
	res, err := f.svc.ApplyDiff(ctx, f.vault.ID, n.ID, DiffInput{Text: "patched 3way", BaseState: snap.State}, "tui", uuid.Nil, "", "")
	if err != nil || res.CRDTEpoch != epoch {
		t.Fatalf("/diff epoch %q err %v", res.CRDTEpoch, err)
	}
	check("3-way diff")

	replica, _ := crdt.LoadDoc(res.State)
	u, _ := replica.ApplyTextDiff("patched 3way!", "apple")
	replica.Close()
	if _, err := f.svc.ApplyUpdate(ctx, f.vault.ID, n.ID, u, "apple", uuid.Nil, "", ""); err != nil {
		t.Fatal(err)
	}
	check("raw update")

	newPath := "moved/keep.md"
	if _, err := f.svc.Update(ctx, f.vault.ID, n.ID, UpdateInput{Path: &newPath}); err != nil {
		t.Fatal(err)
	}
	check("move")

	for i := 0; i < crdt.CompactCountThreshold+2; i++ {
		liveEdit(t, room, web, "edit "+string(rune('a'+i%26)))
	}
	check("compaction")
	f.hub.Leave(room, web)
}

// A vault copy seeds new histories: the copies get fresh epochs.
func TestEpoch_VaultCopyGetsFreshEpochs(t *testing.T) {
	f := newCRDTFixture(t)
	ctx := context.Background()
	n, err := f.svc.Create(ctx, f.vault.ID, CreateInput{Title: "Src", Body: "x"})
	if err != nil {
		t.Fatal(err)
	}
	dst := domain.Vault{ID: uuid.New(), Slug: "dst"}
	if _, err := f.fsm.EnsureVaultDir(dst.Slug); err != nil {
		t.Fatal(err)
	}
	f.svc.vaults.(*fakeVaultLookup).byID[dst.ID] = dst
	if _, err := f.svc.CopyVaultNotes(ctx, f.vault.ID, dst.ID, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	cp, err := f.yjs.notes.Get(ctx, dst.ID, n.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cp.CRDTEpoch == "" || cp.CRDTEpoch == n.CRDTEpoch {
		t.Fatalf("copy epoch %q, source %q: must be fresh", cp.CRDTEpoch, n.CRDTEpoch)
	}
}

// A note announced by a federated peer adopts the peer's epoch.
func TestEpoch_FederationCreateAdoptsPeerEpoch(t *testing.T) {
	f := newCRDTFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	in := domain.Note{ID: "fed", VaultID: f.vault.ID, Path: "fed.md", Title: "Fed", CreatedAt: now, UpdatedAt: now, CRDTEpoch: "peer-epoch"}
	if err := f.svc.CreateFromFederation(ctx, in); err != nil {
		t.Fatal(err)
	}
	if got := f.row(t, "fed").CRDTEpoch; got != "peer-epoch" {
		t.Fatalf("epoch %q, want peer-epoch", got)
	}
	in.CRDTEpoch = "other"
	if err := f.svc.CreateFromFederation(ctx, in); err != nil {
		t.Fatal(err)
	}
	if got := f.row(t, "fed").CRDTEpoch; got != "peer-epoch" {
		t.Fatalf("re-announce changed epoch to %q", got)
	}
}

// ---- HTTP surface ----------------------------------------------------------------

func epochApp(f *crdtFixture, user uuid.UUID) *fiber.App {
	f.svc.resolver = memberResolver{{f.vault.ID, user}: true}
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		if id, err := uuid.Parse(c.Get("X-Test-User")); err == nil {
			capguard.SetUserID(c, id)
		}
		return c.Next()
	})
	NewHandlers(f.svc).Register(app.Group("/api"))
	return app
}

func getJSON(t *testing.T, app *fiber.App, user uuid.UUID, path string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("X-Test-User", user.String())
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(body, &out)
	return resp.StatusCode, out
}

func TestEpoch_HTTPEndpointsExposeEpoch(t *testing.T) {
	f := newCRDTFixture(t)
	ctx := context.Background()
	n, err := f.svc.Create(ctx, f.vault.ID, CreateInput{Title: "Web", Body: "hello"})
	if err != nil {
		t.Fatal(err)
	}
	user := uuid.New()
	app := epochApp(f, user)
	base := "/api/vaults/" + f.vault.ID.String() + "/notes"

	if st, got := getJSON(t, app, user, base+"/"+n.ID); st != 200 || got["crdt_epoch"] != n.CRDTEpoch {
		t.Fatalf("GET note: %d %v", st, got)
	}
	st, snap := getJSON(t, app, user, base+"/"+n.ID+"/snapshot")
	if st != 200 || snap["crdt_epoch"] != n.CRDTEpoch {
		t.Fatalf("GET snapshot: %d %v", st, snap)
	}
	st, sv := getJSON(t, app, user, base+"/"+n.ID+"/state-vector")
	if st != 200 || sv["crdt_epoch"] != n.CRDTEpoch || sv["id"] != n.ID || sv["state_vector"] != snap["vector_clock"] {
		t.Fatalf("GET state-vector: %d %v (snapshot vector_clock %v)", st, sv, snap["vector_clock"])
	}
	if _, ok := sv["state"]; ok {
		t.Fatal("state-vector must not ship the full state")
	}
	if raw, err := base64.StdEncoding.DecodeString(sv["state_vector"].(string)); err != nil {
		t.Fatalf("state_vector not base64: %v", err)
	} else if _, err := crdt.DecodeStateVector(raw); err != nil {
		t.Fatalf("state_vector not a lib0 state vector: %v", err)
	}

	// List and the change feed carry it too.
	req := httptest.NewRequest(http.MethodGet, base, nil)
	req.Header.Set("X-Test-User", user.String())
	resp, _ := app.Test(req, -1)
	var list struct {
		Notes []map[string]any `json:"notes"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&list)
	if len(list.Notes) != 1 || list.Notes[0]["crdt_epoch"] != n.CRDTEpoch {
		t.Fatalf("list: %v", list)
	}
	st, ch := getJSON(t, app, user, "/api/vaults/"+f.vault.ID.String()+"/changes")
	notes, _ := ch["notes"].([]any)
	if st != 200 || len(notes) != 1 || notes[0].(map[string]any)["crdt_epoch"] != n.CRDTEpoch {
		t.Fatalf("changes: %d %v", st, ch)
	}

	if st, _ := getJSON(t, app, user, base+"/missing/state-vector"); st != http.StatusNotFound {
		t.Fatalf("state-vector of a missing note: %d, want 404", st)
	}
	if st, _ := getJSON(t, app, uuid.New(), base+"/"+n.ID+"/state-vector"); st != http.StatusForbidden {
		t.Fatalf("state-vector without note.read: %d, want 403", st)
	}
}
