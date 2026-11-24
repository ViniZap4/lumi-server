package federation

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/crdt"
	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/wsync"
)

func controlDoc(t *testing.T, vaultID uuid.UUID, members ...ControlMember) []byte {
	t.Helper()
	doc := ControlState{V: 1, VaultID: vaultID, Seq: 1, Name: "v",
		Roles: []ControlRole{
			{Name: "Admin", Capabilities: []string{"*"}},
			{Name: "Editor", Capabilities: []string{"note.read", "note.create", "note.edit", "note.delete", "note.move"}},
			{Name: "Viewer", Capabilities: []string{"note.read"}},
			{Name: "Creator", Capabilities: []string{"note.read", "note.create"}},
		},
		Members: members,
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPeerCeiling(t *testing.T) {
	v := uuid.New()
	state := controlDoc(t, v,
		ControlMember{Key: "ana@https://home.example", Role: "Admin"},
		ControlMember{Key: "bob@https://f.example", Role: "Viewer"},
		ControlMember{Key: "cid@https://f.example/", Role: "Creator"},
		ControlMember{Key: "eve@https://other.example", Role: "Editor"},
		ControlMember{Key: "ghost@https://f.example", Role: "Missing"},
	)
	caps := PeerCeiling(state, "https://f.example")
	for _, want := range []domain.Capability{domain.CapNoteRead, domain.CapNoteCreate} {
		if !caps.Has(want) {
			t.Fatalf("ceiling %v lacks %s", caps, want)
		}
	}
	for _, not := range []domain.Capability{domain.CapNoteEdit, domain.CapNoteDelete, domain.CapNoteMove, domain.CapVaultManage} {
		if caps.Has(not) {
			t.Fatalf("ceiling %v must not grant %s (home's or other servers' members leaked in)", caps, not)
		}
	}
	if got := PeerCeiling(state, "https://nobody.example"); len(got) != 0 {
		t.Fatalf("unknown peer ceiling = %v, want empty", got)
	}
	if got := PeerCeiling([]byte("not json"), "https://f.example"); len(got) != 0 {
		t.Fatalf("garbage state ceiling = %v", got)
	}
}

// maliciousPeer runs a home Session against a hand-driven follower end.
type maliciousPeer struct {
	home *relaySide
	conn *pipeConn // follower end: we write raw frames here
	sess *Session
}

func newMaliciousPeer(t *testing.T, home *relaySide, vaultID uuid.UUID) *maliciousPeer {
	t.Helper()
	homeConn, peerConn := newPipePair()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	sess := home.links.NewSession(ctx, homeConn, vaultID, "https://evil.example", "home")
	go func() { _ = sess.Run() }()
	// Drain whatever home sends (opening manifest, Step1s, live fan-out).
	go func() {
		for {
			if _, _, err := peerConn.ReadMessage(); err != nil {
				return
			}
		}
	}()
	return &maliciousPeer{home: home, conn: peerConn, sess: sess}
}

func (m *maliciousPeer) send(t *testing.T, frame []byte) {
	t.Helper()
	if err := m.conn.WriteMessage(binaryMessage, frame); err != nil {
		t.Fatal(err)
	}
}

// updateFor builds a real Yjs update that rewrites the note's text,
// starting from home's current state (what a follower replica holds).
func updateFor(t *testing.T, side *relaySide, vaultID uuid.UUID, noteID, newText string) []byte {
	t.Helper()
	doc, err := side.registry.LoadDoc(context.Background(), vaultID, noteID)
	if err != nil {
		t.Fatal(err)
	}
	state, err := doc.EncodeStateAsUpdate()
	doc.Close()
	if err != nil {
		t.Fatal(err)
	}
	replica, err := crdt.LoadDoc(state)
	if err != nil {
		t.Fatal(err)
	}
	defer replica.Close()
	update, err := replica.ApplyTextDiff(newText, "evil")
	if err != nil {
		t.Fatal(err)
	}
	return update
}

func deniedFrames(side *relaySide) map[string]bool {
	out := map[string]bool{}
	for _, a := range side.auditActions() {
		if a.action == domain.ActionFederationPeerDenied {
			out[a.payload["frame"].(string)] = true
		}
	}
	return out
}

// TestRelay_HomeRejectsUnauthorizedFollowerWrites is the G3 regression: a
// follower whose users home granted only note.read cannot create, edit,
// move or delete anything on home, whatever frames it forges.
func TestRelay_HomeRejectsUnauthorizedFollowerWrites(t *testing.T) {
	vaultID := uuid.New()
	home := newRelaySide(t)
	home.setCaps(domain.CapabilitySet{domain.CapNoteRead})
	home.seedNote(t, vaultID, "alpha", "alpha.md", "Alpha", "home text")
	ctx := context.Background()

	peer := newMaliciousPeer(t, home, vaultID)

	peer.send(t, EncodeNoteSync("alpha", wsync.EncodeSyncUpdate(updateFor(t, home, vaultID, "alpha", "defaced"))))
	peer.send(t, EncodeNoteSync("alpha", wsync.EncodeSyncStep2(updateFor(t, home, vaultID, "alpha", "defaced too"))))
	peer.send(t, EncodeNoteMove(NoteMeta{ID: "alpha", Path: "moved/alpha.md", Title: "Alpha"}))
	peer.send(t, EncodeNoteMove(NoteMeta{ID: "alpha", Path: "alpha.md", Title: "Retitled"}))
	peer.send(t, EncodeNoteAnnounce(NoteMeta{ID: "evil", Path: "evil.md", Title: "Evil"}))
	peer.send(t, EncodeManifest([]NoteMeta{{ID: "evil2", Path: "evil2.md", Title: "Evil 2"}}))
	peer.send(t, EncodeNoteDelete("alpha"))
	// A no-op Step2 (what an up-to-date honest replica answers) is fine.
	peer.send(t, EncodeNoteSync("alpha", wsync.EncodeSyncStep2([]byte{0, 0})))

	waitFor(t, "every forged frame audited", func() bool {
		d := deniedFrames(home)
		return d["note_sync"] && d["move"] && d["announce"] && d["manifest"] && d["delete"]
	})
	n, err := home.notes.Get(ctx, vaultID, "alpha")
	if err != nil {
		t.Fatalf("alpha deleted on home: %v", err)
	}
	if n.Path != "alpha.md" || n.Title != "Alpha" {
		t.Fatalf("alpha moved/retitled on home: %+v", n)
	}
	if got := home.text(t, vaultID, "alpha"); got != "home text" {
		t.Fatalf("alpha content changed on home: %q", got)
	}
	for _, id := range []string{"evil", "evil2"} {
		if _, err := home.notes.Get(ctx, vaultID, id); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("forged note %q created on home: %v", id, err)
		}
	}
	// Denials are deduplicated per (frame, note, reason) on a connection.
	count := 0
	for _, a := range home.auditActions() {
		if a.action == domain.ActionFederationPeerDenied && a.payload["frame"] == "note_sync" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("note_sync denials audited %d times, want 1", count)
	}
	// The link stays up for an honest-but-unprivileged replica.
	select {
	case <-peer.sess.done:
		t.Fatal("replica link closed on a denied frame")
	default:
	}
}

// The ceiling follows home's control state live: a grant pushed to the
// link takes effect for the next frame, a removal too.
func TestRelay_PeerCeilingFollowsControlPush(t *testing.T) {
	vaultID := uuid.New()
	home := newRelaySide(t)
	home.setCaps(domain.CapabilitySet{}) // nothing at session open
	home.seedNote(t, vaultID, "alpha", "alpha.md", "Alpha", "home text")
	home.seedNote(t, vaultID, "beta", "beta.md", "Beta", "beta text")
	ctx := context.Background()
	peer := newMaliciousPeer(t, home, vaultID)

	peer.send(t, EncodeNoteDelete("alpha"))
	waitFor(t, "delete denied", func() bool { return deniedFrames(home)["delete"] })
	if _, err := home.notes.Get(ctx, vaultID, "alpha"); err != nil {
		t.Fatalf("alpha gone: %v", err)
	}

	// Home grants an Editor on the peer server.
	home.links.PushControl(vaultID, controlDoc(t, vaultID,
		ControlMember{Key: "bob@https://evil.example", Role: "Editor"}), []byte("sig"))
	peer.send(t, EncodeNoteDelete("alpha"))
	waitFor(t, "authorized delete applied", func() bool {
		_, err := home.notes.Get(ctx, vaultID, "alpha")
		return errors.Is(err, domain.ErrNotFound)
	})
	peer.send(t, EncodeNoteSync("beta", wsync.EncodeSyncUpdate(updateFor(t, home, vaultID, "beta", "edited by bob"))))
	waitFor(t, "authorized edit applied", func() bool { return home.text(t, vaultID, "beta") == "edited by bob" })

	// And takes it away again.
	home.links.PushControl(vaultID, controlDoc(t, vaultID), []byte("sig"))
	peer.send(t, EncodeNoteSync("beta", wsync.EncodeSyncUpdate(updateFor(t, home, vaultID, "beta", "after revoke"))))
	time.Sleep(200 * time.Millisecond)
	if got := home.text(t, vaultID, "beta"); got != "edited by bob" {
		t.Fatalf("edit after the grant was removed applied: %q", got)
	}
}

// note.create without note.edit: the link may create a note and send its
// initial content, but not edit notes it did not create.
func TestRelay_CreateOnlyPeer(t *testing.T) {
	vaultID := uuid.New()
	home := newRelaySide(t)
	home.setCaps(domain.CapabilitySet{domain.CapNoteRead, domain.CapNoteCreate})
	home.seedNote(t, vaultID, "alpha", "alpha.md", "Alpha", "home text")
	ctx := context.Background()
	peer := newMaliciousPeer(t, home, vaultID)

	fresh := crdt.NewDoc()
	defer fresh.Close()
	upd, err := fresh.ApplyTextDiff("brand new", "peer")
	if err != nil {
		t.Fatal(err)
	}
	peer.send(t, EncodeNoteAnnounce(NoteMeta{ID: "gamma", Path: "gamma.md", Title: "Gamma"}))
	peer.send(t, EncodeNoteSync("gamma", wsync.EncodeSyncUpdate(upd)))
	waitFor(t, "created note content on home", func() bool {
		if _, err := home.notes.Get(ctx, vaultID, "gamma"); err != nil {
			return false
		}
		return home.text(t, vaultID, "gamma") == "brand new"
	})
	peer.send(t, EncodeNoteSync("alpha", wsync.EncodeSyncUpdate(updateFor(t, home, vaultID, "alpha", "nope"))))
	waitFor(t, "edit of an existing note denied", func() bool { return deniedFrames(home)["note_sync"] })
	if got := home.text(t, vaultID, "alpha"); got != "home text" {
		t.Fatalf("alpha edited: %q", got)
	}
}

// Without a PeerCaps source home denies every follower write (fail closed).
func TestRelay_NoPeerCapsFailsClosed(t *testing.T) {
	vaultID := uuid.New()
	home := newRelaySide(t)
	home.links.deps.PeerCaps = nil
	home.seedNote(t, vaultID, "alpha", "alpha.md", "Alpha", "home text")
	peer := newMaliciousPeer(t, home, vaultID)
	peer.send(t, EncodeNoteDelete("alpha"))
	waitFor(t, "delete denied", func() bool { return deniedFrames(home)["delete"] })
	if _, err := home.notes.Get(context.Background(), vaultID, "alpha"); err != nil {
		t.Fatalf("alpha deleted without a ceiling: %v", err)
	}
}
