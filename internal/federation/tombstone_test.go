package federation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// seedEpoch seeds a note with an explicit CRDT epoch.
func (rs *relaySide) seedEpoch(t *testing.T, vaultID uuid.UUID, id, body, epoch string) {
	t.Helper()
	if err := rs.notes.Upsert(context.Background(), domain.Note{
		ID: id, VaultID: vaultID, Path: id + ".md", Title: id,
		CreatedAt: time.Now(), UpdatedAt: time.Now(), CRDTEpoch: epoch,
	}); err != nil {
		t.Fatal(err)
	}
	if err := rs.registry.InitFromText(context.Background(), vaultID, id, body, uuid.Nil, "seed"); err != nil {
		t.Fatal(err)
	}
}

// link connects home and follower over a fresh pipe; the returned func
// takes the link down (both sessions end) and waits for it.
func link(t *testing.T, home, follower *relaySide, vaultID uuid.UUID) func() {
	t.Helper()
	homeConn, followerConn := newPipePair()
	ctx, cancel := context.WithCancel(context.Background())
	hs := home.links.NewSession(ctx, homeConn, vaultID, "https://follower.example", "home")
	fs := follower.links.NewSession(ctx, followerConn, vaultID, "https://home.example", "follower")
	done := make(chan struct{}, 2)
	go func() { _ = hs.Run(); done <- struct{}{} }()
	go func() { _ = fs.Run(); done <- struct{}{} }()
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		<-done
		<-done
	}
	t.Cleanup(stop)
	return stop
}

func hasNote(rs *relaySide, vaultID uuid.UUID, id string) bool {
	_, err := rs.notes.Get(context.Background(), vaultID, id)
	return err == nil
}

// TestRelay_OfflineFollowerDoesNotResurrectHomeDeletes is the G2
// regression: home deletes a note while the follower is offline; on
// reconnect the follower re-announces it and home must answer with the
// delete, not recreate it. A note the follower created offline still
// reaches home.
func TestRelay_OfflineFollowerDoesNotResurrectHomeDeletes(t *testing.T) {
	vaultID := uuid.New()
	home, follower := newRelaySide(t), newRelaySide(t)
	home.seedEpoch(t, vaultID, "alpha", "doomed", "e-alpha-1")
	home.seedEpoch(t, vaultID, "keep", "kept", "e-keep-1")

	stop := link(t, home, follower, vaultID)
	waitFor(t, "alpha on follower", func() bool {
		text, ok := follower.mirror.get(vaultID, "alpha")
		return ok && text == "doomed"
	})
	if n, _ := follower.notes.Get(context.Background(), vaultID, "alpha"); n.CRDTEpoch != "e-alpha-1" {
		t.Fatalf("follower did not adopt home's epoch: %+v", n)
	}
	stop()

	// Offline: home deletes alpha, the follower writes a new note.
	if err := home.notes.delete(vaultID, "alpha"); err != nil {
		t.Fatal(err)
	}
	follower.seedEpoch(t, vaultID, "fresh", "made offline", "e-fresh-1")

	link(t, home, follower, vaultID)
	waitFor(t, "alpha deleted on the follower", func() bool { return !hasNote(follower, vaultID, "alpha") })
	waitFor(t, "fresh note reaches home", func() bool {
		text, ok := home.mirror.get(vaultID, "fresh")
		return ok && text == "made offline"
	})
	time.Sleep(100 * time.Millisecond)
	if hasNote(home, vaultID, "alpha") {
		t.Fatal("home resurrected a note it deleted")
	}
	if !hasNote(follower, vaultID, "keep") {
		t.Fatal("untouched note lost")
	}
}

// A follower that deleted a note while offline sends the delete on
// reconnect instead of recreating it; home applies it when the link's
// users may delete.
func TestRelay_OfflineFollowerDeletePropagates(t *testing.T) {
	vaultID := uuid.New()
	home, follower := newRelaySide(t), newRelaySide(t)
	home.seedEpoch(t, vaultID, "alpha", "text", "e-alpha-1")

	stop := link(t, home, follower, vaultID)
	waitFor(t, "alpha on follower", func() bool { return hasNote(follower, vaultID, "alpha") })
	stop()
	if err := follower.notes.delete(vaultID, "alpha"); err != nil {
		t.Fatal(err)
	}

	link(t, home, follower, vaultID)
	waitFor(t, "offline delete reaches home", func() bool { return !hasNote(home, vaultID, "alpha") })
	time.Sleep(100 * time.Millisecond)
	if hasNote(follower, vaultID, "alpha") {
		t.Fatal("follower recreated the note it deleted")
	}
}

// Same, but the link's users may not delete: home refuses (G3) and gives
// the follower its copy back, so the two sides do not stay diverged.
func TestRelay_OfflineFollowerDeleteRefusedIsRestored(t *testing.T) {
	vaultID := uuid.New()
	home, follower := newRelaySide(t), newRelaySide(t)
	home.setCaps(domain.CapabilitySet{domain.CapNoteRead, domain.CapNoteEdit})
	home.seedEpoch(t, vaultID, "alpha", "text", "e-alpha-1")

	stop := link(t, home, follower, vaultID)
	waitFor(t, "alpha on follower", func() bool { return hasNote(follower, vaultID, "alpha") })
	stop()
	if err := follower.notes.delete(vaultID, "alpha"); err != nil {
		t.Fatal(err)
	}

	link(t, home, follower, vaultID)
	waitFor(t, "denied delete audited", func() bool { return deniedFrames(home)["delete"] })
	waitFor(t, "alpha restored on the follower", func() bool { return hasNote(follower, vaultID, "alpha") })
	if !hasNote(home, vaultID, "alpha") {
		t.Fatal("unauthorized offline delete applied at home")
	}
}

// Home deleted and recreated the id (new history) while the follower was
// away: the follower's tombstone names the old epoch, so it adopts the
// new note instead of sending a delete for it.
func TestRelay_RecreatedIDIsNotTreatedAsDeleted(t *testing.T) {
	vaultID := uuid.New()
	home, follower := newRelaySide(t), newRelaySide(t)
	home.seedEpoch(t, vaultID, "alpha", "v1", "e-alpha-1")

	stop := link(t, home, follower, vaultID)
	waitFor(t, "alpha on follower", func() bool { return hasNote(follower, vaultID, "alpha") })
	if err := home.notes.delete(vaultID, "alpha"); err != nil {
		t.Fatal(err)
	}
	home.links.NoteDeleted(vaultID, "alpha")
	waitFor(t, "live delete on follower", func() bool { return !hasNote(follower, vaultID, "alpha") })
	stop()

	// Fresh registry state for the new history under the same id.
	home.repo.mu.Lock()
	delete(home.repo.snaps, snKey(vaultID, "alpha"))
	delete(home.repo.updates, snKey(vaultID, "alpha"))
	home.repo.mu.Unlock()
	home.seedEpoch(t, vaultID, "alpha", "v2", "e-alpha-2")

	link(t, home, follower, vaultID)
	waitFor(t, "recreated alpha on follower", func() bool {
		n, err := follower.notes.Get(context.Background(), vaultID, "alpha")
		return err == nil && n.CRDTEpoch == "e-alpha-2"
	})
	if !hasNote(home, vaultID, "alpha") {
		t.Fatal("home lost the recreated note")
	}
	_, err := home.notes.Get(context.Background(), vaultID, "alpha")
	if errors.Is(err, domain.ErrNotFound) {
		t.Fatal("recreated note deleted")
	}
}
