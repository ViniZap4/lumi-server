package federation

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// Epochs ride as optional trailing data (protocol §12): round-trip with
// them, decode frames from peers predating them, and stay decodable by
// such peers (they stop reading after the fields they know).
func TestFrameCodec_EpochsOptionalTrailing(t *testing.T) {
	metas := []NoteMeta{
		{ID: "a", Path: "a.md", Title: "A", Epoch: "e-a"},
		{ID: "b", Path: "b.md", Title: "B"}, // unknown epoch
	}
	f, err := DecodeFrame(EncodeManifest(metas))
	if err != nil || len(f.Manifest) != 2 || f.Manifest[0].Epoch != "e-a" || f.Manifest[1].Epoch != "" {
		t.Fatalf("manifest with epochs: %+v %v", f, err)
	}

	// Old-format manifest (no trailing list) still decodes.
	old := writeVarUint(nil, frameManifest)
	old = writeVarUint(old, 1)
	old = appendNoteMeta(old, NoteMeta{ID: "a", Path: "a.md", Title: "A"})
	if f, err := DecodeFrame(old); err != nil || len(f.Manifest) != 1 || f.Manifest[0].Epoch != "" {
		t.Fatalf("legacy manifest: %+v %v", f, err)
	}
	// A new manifest's prefix is exactly the legacy encoding.
	if got := EncodeManifest([]NoteMeta{{ID: "a", Path: "a.md", Title: "A", Epoch: "e"}}); string(got[:len(old)]) != string(old) {
		t.Fatal("epoch list must be appended after the legacy manifest bytes")
	}
	// Mismatched epoch count is malformed.
	bad := writeVarUint(append([]byte(nil), old...), 2)
	if _, err := DecodeFrame(bad); err == nil {
		t.Fatal("epoch count != note count must error")
	}

	f, err = DecodeFrame(EncodeNoteAnnounce(NoteMeta{ID: "g", Path: "g.md", Title: "G", Epoch: "e-g"}))
	if err != nil || f.Note.Epoch != "e-g" || f.Note.ID != "g" {
		t.Fatalf("announce with epoch: %+v %v", f, err)
	}
	f, err = DecodeFrame(EncodeNoteAnnounce(NoteMeta{ID: "g", Path: "g.md", Title: "G"}))
	if err != nil || f.Note.Epoch != "" {
		t.Fatalf("announce without epoch: %+v %v", f, err)
	}
	long := make([]byte, maxNoteEpochBytes+1)
	for i := range long {
		long[i] = 'x'
	}
	if _, err := DecodeFrame(EncodeNoteAnnounce(NoteMeta{ID: "g", Path: "g.md", Title: "G", Epoch: string(long)})); err == nil {
		t.Fatal("oversized epoch must error")
	}
}

// The peer creating a note row from a manifest or an announce adopts the
// sender's epoch: the doc it receives over the relay is that history.
func TestRelay_PropagatesEpochOnCreate(t *testing.T) {
	vaultID := uuid.New()
	home := newRelaySide(t)
	follower := newRelaySide(t)
	ctx := context.Background()

	seed := func(rs *relaySide, id, epoch string) {
		t.Helper()
		if err := rs.notes.Upsert(ctx, domain.Note{ID: id, VaultID: vaultID, Path: id + ".md", Title: id,
			CreatedAt: time.Now(), UpdatedAt: time.Now(), CRDTEpoch: epoch}); err != nil {
			t.Fatal(err)
		}
		if _, err := rs.registry.InitFromTextEpoch(ctx, vaultID, id, "body "+id, epoch, uuid.Nil, "seed"); err != nil {
			t.Fatal(err)
		}
	}
	seed(home, "alpha", "epoch-alpha")       // reaches the follower via manifest
	seed(follower, "beta", "epoch-beta")     // reaches home via announce
	seed(follower, "shared", "follower-own") // exists on both: kept as is
	seed(home, "shared", "home-own")

	homeConn, followerConn := newPipePair()
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = home.links.NewSession(cctx, homeConn, vaultID, "https://follower.example", "home").Run() }()
	go func() {
		_ = follower.links.NewSession(cctx, followerConn, vaultID, "https://home.example", "follower").Run()
	}()

	epochOf := func(rs *relaySide, id string) string {
		n, err := rs.notes.Get(ctx, vaultID, id)
		if err != nil {
			return ""
		}
		return n.CRDTEpoch
	}
	waitFor(t, "alpha epoch on follower", func() bool { return epochOf(follower, "alpha") == "epoch-alpha" })
	waitFor(t, "beta epoch on home", func() bool { return epochOf(home, "beta") == "epoch-beta" })
	if epochOf(follower, "shared") != "follower-own" || epochOf(home, "shared") != "home-own" {
		t.Fatal("an existing row's epoch must not be overwritten by a peer")
	}

	// A note created while the link is up: NoteCreated announces it with
	// its epoch.
	seed(home, "gamma", "epoch-gamma")
	home.links.NoteCreated(vaultID, "gamma", "gamma.md", "gamma")
	waitFor(t, "gamma epoch on follower", func() bool { return epochOf(follower, "gamma") == "epoch-gamma" })
}
