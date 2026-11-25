package federation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/wsync"
)

// spyConn records every frame one side writes.
type spyConn struct {
	*pipeConn
	mu     sync.Mutex
	frames [][]byte
}

func (s *spyConn) WriteMessage(t int, data []byte) error {
	s.mu.Lock()
	s.frames = append(s.frames, append([]byte(nil), data...))
	s.mu.Unlock()
	return s.pipeConn.WriteMessage(t, data)
}

func (s *spyConn) decoded(t *testing.T) []Frame {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Frame, 0, len(s.frames))
	for _, b := range s.frames {
		f, err := DecodeFrame(b)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, f)
	}
	return out
}

func (s *spyConn) contains(needle string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.frames {
		if bytes.Contains(b, []byte(needle)) {
			return true
		}
	}
	return false
}

func (s *spyConn) count(typ uint64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, b := range s.frames {
		if f, err := DecodeFrame(b); err == nil && f.Type == typ {
			n++
		}
	}
	return n
}

// changeLog is a fake home change log (notes.Service.Changes).
type changeLog struct {
	mu    sync.Mutex
	notes *memNoteRepo
	seqs  map[string]int64 // note id → change_seq
	tombs []domain.NoteTombstone
	floor int64
	head  int64
}

func newChangeLog(notes *memNoteRepo) *changeLog {
	return &changeLog{notes: notes, seqs: map[string]int64{}}
}

func (c *changeLog) touch(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.head++
	c.seqs[id] = c.head
}

func (c *changeLog) tomb(id string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.head++
	delete(c.seqs, id)
	c.tombs = append(c.tombs, domain.NoteTombstone{ID: id, Seq: c.head})
}

func (c *changeLog) changes(ctx context.Context, vaultID uuid.UUID, after int64, limit int) (domain.NoteChanges, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if after > 0 && after < c.floor {
		return domain.NoteChanges{}, &domain.ResyncRequiredError{Head: c.head}
	}
	out := domain.NoteChanges{Head: c.head}
	for id, seq := range c.seqs {
		if seq > after {
			n, err := c.notes.Get(ctx, vaultID, id)
			if err != nil {
				continue
			}
			n.ChangeSeq = seq
			out.Notes = append(out.Notes, n)
		}
	}
	sort.Slice(out.Notes, func(i, j int) bool { return out.Notes[i].ChangeSeq < out.Notes[j].ChangeSeq })
	for _, tb := range c.tombs {
		if tb.Seq > after {
			out.Deleted = append(out.Deleted, tb)
		}
	}
	return out, nil
}

func (c *changeLog) headSeq() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.head
}

// resumeLink connects a resuming mirror (home_seq = from); the home conn
// is spied.
func resumeLink(t *testing.T, home, mirror *relaySide, vaultID uuid.UUID, from int64, publish *PublishPolicy) (stop func(), spy *spyConn, hs, ms *Session) {
	t.Helper()
	homeConn, mirrorConn := newPipePair()
	spy = &spyConn{pipeConn: homeConn}
	ctx, cancel := context.WithCancel(context.Background())
	hs = home.links.NewSessionWith(ctx, spy, vaultID, "https://mirror.example", "home",
		SessionOptions{Mode: ModeMirror, PeerProto: RelayProtoVersion, ExpectResume: true, Publish: publish})
	ms = mirror.links.NewSessionWith(ctx, mirrorConn, vaultID, "https://home.example", "follower",
		SessionOptions{Mode: ModeMirror, SendResume: true, ResumeFrom: from})
	done := make(chan struct{}, 2)
	go func() { _ = hs.Run(); done <- struct{}{} }()
	go func() { _ = ms.Run(); done <- struct{}{} }()
	stopped := false
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		<-done
		<-done
	}
	t.Cleanup(stop)
	return stop, spy, hs, ms
}

// §A7.2: a mirror that resumes from home_seq gets only the changes after
// it (no manifest): an edited note, a deleted one, a created one; it then
// acknowledges home's head.
func TestMirror_ResumeSendsOnlyChanges(t *testing.T) {
	vaultID := uuid.New()
	home, mirror := newRelaySide(t), newRelaySide(t)
	hooks := &mirrorHooks{}
	hooks.install(home, mirror)
	log := newChangeLog(home.notes)
	home.links.deps.Changes = log.changes
	home.links.deps.Head = func(context.Context, uuid.UUID) (int64, error) { return log.headSeq(), nil }
	for _, id := range []string{"a", "b", "c"} {
		home.seedEpoch(t, vaultID, id, "text "+id, "e-"+id)
		log.touch(id)
	}
	stop, _, _ := mirrorLink(t, home, mirror, vaultID)
	waitFor(t, "initial backfill", func() bool { acked, _, _, _ := hooks.snapshot(); return acked == 3 })
	stop()

	// Offline at home: edit b, delete c, create d.
	home.localEdit(t, vaultID, "b", "b edited offline")
	log.touch("b")
	_ = home.notes.delete(vaultID, "c")
	log.tomb("c")
	home.seedEpoch(t, vaultID, "d", "text d", "e-d")
	log.touch("d")

	_, spy, _, _ := resumeLink(t, home, mirror, vaultID, 3, nil)
	waitFor(t, "resume applied", func() bool {
		b, _ := mirror.mirror.get(vaultID, "b")
		d, _ := mirror.mirror.get(vaultID, "d")
		return b == "b edited offline" && d == "text d" && !hasNote(mirror, vaultID, "c")
	})
	waitFor(t, "head acknowledged after the resume", func() bool {
		acked, homeSeq, _, _ := hooks.snapshot()
		return acked == log.headSeq() && homeSeq == log.headSeq()
	})
	if n := spy.count(frameManifest); n != 0 {
		t.Fatalf("resume sent %d manifest(s)", n)
	}
	// Only the changed notes were announced.
	var announced []string
	for _, f := range spy.decoded(t) {
		if f.Type == frameNoteAnnounce {
			announced = append(announced, f.Note.ID)
		}
	}
	sort.Strings(announced)
	if len(announced) != 2 || announced[0] != "b" || announced[1] != "d" {
		t.Fatalf("announced %v", announced)
	}
	if !hasNote(mirror, vaultID, "a") {
		t.Fatal("an unchanged note was lost")
	}
}

// A19 #5: a resume cursor below the tombstone floor falls back to the
// full manifest, which still deletes what home no longer has.
func TestMirror_ResumeBelowFloorFallsBackToManifest(t *testing.T) {
	vaultID := uuid.New()
	home, mirror := newRelaySide(t), newRelaySide(t)
	hooks := &mirrorHooks{}
	hooks.install(home, mirror)
	log := newChangeLog(home.notes)
	home.links.deps.Changes = log.changes
	home.links.deps.Head = func(context.Context, uuid.UUID) (int64, error) { return log.headSeq(), nil }
	home.seedEpoch(t, vaultID, "keep", "kept", "e-k")
	log.touch("keep")
	mirror.seedEpoch(t, vaultID, "keep", "kept", "e-k")
	mirror.seedEpoch(t, vaultID, "pruned", "old", "e-p") // home deleted it long ago
	log.head, log.floor = 50, 40                         // its tombstone was pruned

	_, spy, _, _ := resumeLink(t, home, mirror, vaultID, 10, nil)
	waitFor(t, "absent note deleted", func() bool { return !hasNote(mirror, vaultID, "pruned") })
	waitFor(t, "manifest sent", func() bool { return spy.count(frameManifest) == 1 })
	waitFor(t, "acked", func() bool { acked, _, _, _ := hooks.snapshot(); return acked == 50 })
}

// A home that predates resume ignores frameResumeFrom; a home that waits
// for one from a mirror that never sends it falls back after resumeWait.
func TestMirror_ResumeWaitTimesOut(t *testing.T) {
	old := resumeWait
	resumeWait = 100 * time.Millisecond
	t.Cleanup(func() { resumeWait = old })
	vaultID := uuid.New()
	home := newRelaySide(t)
	(&mirrorHooks{}).install(home, nil)
	home.seedEpoch(t, vaultID, "a", "x", "e")
	homeConn, peer := newPipePair()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hs := home.links.NewSessionWith(ctx, homeConn, vaultID, "https://mirror.example", "home",
		SessionOptions{Mode: ModeMirror, PeerProto: RelayProtoVersion, ExpectResume: true})
	go func() { _ = hs.Run() }()
	select {
	case msg := <-peer.in:
		if f, _ := DecodeFrame(msg); f.Type != frameManifest {
			t.Fatalf("first frame %d", f.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no opening after the resume wait")
	}
}

func withResetDoc(rs *relaySide) {
	rs.links.deps.ResetDoc = func(_ context.Context, vaultID uuid.UUID, noteID string) error {
		rs.repo.mu.Lock()
		defer rs.repo.mu.Unlock()
		delete(rs.repo.snaps, snKey(vaultID, noteID))
		delete(rs.repo.updates, snKey(vaultID, noteID))
		return nil
	}
}

// §A9: a mirror copy holding operations home never had is reported on
// both sides and rebuilt from home's full state under the same epoch.
func TestMirror_DivergenceDetectedAndRebuilt(t *testing.T) {
	vaultID := uuid.New()
	home, mirror := newRelaySide(t), newRelaySide(t)
	(&mirrorHooks{}).install(home, mirror)
	withResetDoc(mirror)
	var mu sync.Mutex
	sides := map[string]int{}
	report := func(_ uuid.UUID, _, _, side string) { mu.Lock(); sides[side]++; mu.Unlock() }
	home.links.deps.Divergent = report
	mirror.links.deps.Divergent = report

	home.seedEpoch(t, vaultID, "alpha", "home text", "e1")
	// The mirror's copy has a history of its own (a restored foreign
	// backup, or tampering) under the same epoch.
	mirror.seedEpoch(t, vaultID, "alpha", "foreign text", "e1")

	mirrorLink(t, home, mirror, vaultID)
	waitFor(t, "rebuilt to home's text", func() bool { return mirror.text(t, vaultID, "alpha") == "home text" })
	mu.Lock()
	defer mu.Unlock()
	if sides["home"] == 0 || sides["mirror"] == 0 {
		t.Fatalf("divergence reports = %v", sides)
	}
	var audited bool
	for _, a := range home.auditActions() {
		if a.action == domain.ActionFederationMirrorDivergent && a.payload["note_id"] == "alpha" {
			audited = true
		}
	}
	if !audited {
		t.Fatal("home did not audit federation.mirror_divergent")
	}
	if n, _ := mirror.notes.Get(context.Background(), vaultID, "alpha"); n.CRDTEpoch != "e1" {
		t.Fatalf("rebuild changed the epoch: %q", n.CRDTEpoch)
	}
}

// §A10: the integrity pass rewrites a file whose body drifted from the
// CRDT text and leaves matching files alone.
func TestMirror_IntegrityPassRewritesDriftedFiles(t *testing.T) {
	old := integrityRate
	integrityRate = 1000
	t.Cleanup(func() { integrityRate = old })
	vaultID := uuid.New()
	home, mirror := newRelaySide(t), newRelaySide(t)
	hooks := &mirrorHooks{}
	hooks.install(home, mirror)
	home.seedEpoch(t, vaultID, "ok", "fine", "e1")
	home.seedEpoch(t, vaultID, "drift", "true text", "e2")
	_, _, ms := mirrorLink(t, home, mirror, vaultID)
	waitFor(t, "backfill", func() bool { return !ms.backfillProgress().Active && mirror.text(t, vaultID, "drift") == "true text" })

	disk := map[string]string{"ok": "fine", "drift": "edited behind lumi's back"}
	var diskMu sync.Mutex
	mirror.links.deps.ReadBody = func(_ context.Context, _ uuid.UUID, id string) (string, error) {
		diskMu.Lock()
		defer diskMu.Unlock()
		b, ok := disk[id]
		if !ok {
			return "", domain.ErrNotFound
		}
		return b, nil
	}
	ms.deps.ReadBody = mirror.links.deps.ReadBody
	mirror.mirror.mu.Lock()
	mirror.mirror.texts = map[string]string{}
	mirror.mirror.mu.Unlock()

	// (The pass's Step1s also bring [0,0] Step2s back; Rewritten counts
	// only the integrity rewrites.)
	r := ms.integrityPass()
	if r.Notes != 2 || r.Rewritten != 1 || r.Errors != 0 {
		t.Fatalf("report = %+v", r)
	}
	if got, _ := mirror.mirror.get(vaultID, "drift"); got != "true text" {
		t.Fatalf("drifted file rewritten with %q", got)
	}
}

// ---- publish mirrors (M3) --------------------------------------------------------

// A19 #8 and §A16: on a publish link (scope flagged) a note without
// publish: true never appears in any frame home sends, whatever happens to
// it; flipping the flag on publishes it, flipping it off deletes it on the
// mirror; a Step1 for an unpublished id gets no answer.
func TestPublish_HomeFiltersEveryFrame(t *testing.T) {
	vaultID := uuid.New()
	home, mirror := newRelaySide(t), newRelaySide(t)
	(&mirrorHooks{}).install(home, mirror)
	fm := withFM(home)
	withFM(mirror)
	home.seedEpoch(t, vaultID, "pub", "public words", "e1")
	fm.docs["pub"] = `{"publish":true,"tags":["x"]}`
	home.seedEpoch(t, vaultID, "secret-note", "SECRET-BODY", "e2")
	fm.docs["secret-note"] = `{"publish":false,"tags":["private"]}`
	home.seedEpoch(t, vaultID, "plain", "PLAIN-BODY", "e3")

	policy := &PublishPolicy{Allowed: true, Scope: PublishScopeFlagged}
	_, spy, _, _ := resumeLink(t, home, mirror, vaultID, 7, policy)
	waitFor(t, "published note on the mirror", func() bool { return mirror.text(t, vaultID, "pub") == "public words" })
	if n := spy.count(frameManifest); n != 1 {
		t.Fatalf("a publish link must open with the manifest (resume would leak tombstone ids), got %d", n)
	}

	// Everything that can happen to the private notes at home.
	home.localEdit(t, vaultID, "secret-note", "SECRET-BODY edited")
	home.links.NoteMetaChanged(vaultID, "secret-note")
	home.links.NoteMoved(vaultID, "plain", "dir/plain.md", "plain")
	_ = home.notes.delete(vaultID, "plain")
	home.links.NoteDeleted(vaultID, "plain")
	home.seedEpoch(t, vaultID, "new-secret", "NEW-SECRET-BODY", "e4")
	home.links.NoteCreated(vaultID, "new-secret", "new-secret.md", "new-secret")
	// A mirror asking for an id it should not know.
	_ = mirror.links.sessionsFor(vaultID)[0].conn.WriteMessage(binaryMessage,
		EncodeNoteSync("secret-note", wsync.EncodeSyncStep1([]byte{0})))
	time.Sleep(200 * time.Millisecond)
	for _, needle := range []string{"secret-note", "SECRET-BODY", "plain", "PLAIN-BODY", "new-secret", "NEW-SECRET", "private"} {
		if spy.contains(needle) {
			t.Fatalf("%q crossed a publish link", needle)
		}
	}
	if hasNote(mirror, vaultID, "secret-note") || hasNote(mirror, vaultID, "plain") {
		t.Fatal("unpublished note reached the mirror")
	}

	// Flip the flag on: the note is published (announce + state).
	fm.mu.Lock()
	fm.docs["secret-note"] = `{"publish":true}`
	fm.mu.Unlock()
	home.links.NoteMetaChanged(vaultID, "secret-note")
	waitFor(t, "flagged note published", func() bool {
		return hasNote(mirror, vaultID, "secret-note") && mirror.text(t, vaultID, "secret-note") == "SECRET-BODY edited"
	})
	// Flip the published one off: deleted on the mirror.
	fm.mu.Lock()
	fm.docs["pub"] = `{"tags":["x"]}`
	fm.mu.Unlock()
	home.links.NoteMetaChanged(vaultID, "pub")
	waitFor(t, "unflagged note deleted on the mirror", func() bool { return !hasNote(mirror, vaultID, "pub") })
	// Edits of the unpublished note no longer flow.
	before := len(spy.decoded(t))
	home.localEdit(t, vaultID, "pub", "edited after unpublish")
	time.Sleep(100 * time.Millisecond)
	if spy.contains("edited after unpublish") || len(spy.decoded(t)) > before+1 {
		t.Fatal("an unpublished note's edit crossed the link")
	}
}

func TestPublish_FolderScopeMoves(t *testing.T) {
	vaultID := uuid.New()
	home, mirror := newRelaySide(t), newRelaySide(t)
	(&mirrorHooks{}).install(home, mirror)
	home.seedNote(t, vaultID, "in", "blog/in.md", "in", "IN-BODY")
	home.seedNote(t, vaultID, "out", "drafts/out.md", "out", "OUT-BODY")
	policy := &PublishPolicy{Allowed: true, Scope: "folder:blog"}
	_, spy, _, _ := resumeLink(t, home, mirror, vaultID, 0, policy)
	waitFor(t, "folder note published", func() bool { return mirror.text(t, vaultID, "in") == "IN-BODY" })
	if spy.contains("OUT-BODY") || spy.contains("drafts") {
		t.Fatal("out-of-folder note crossed the link")
	}
	// Moving out of the folder unpublishes; moving in publishes.
	moveAtHome := func(id, path string) {
		n, _ := home.notes.Get(context.Background(), vaultID, id)
		n.Path = path
		_ = home.notes.Upsert(context.Background(), n)
		home.links.NoteMoved(vaultID, id, path, n.Title)
	}
	moveAtHome("in", "drafts/in.md")
	waitFor(t, "moved-out note deleted", func() bool { return !hasNote(mirror, vaultID, "in") })
	moveAtHome("out", "blog/out.md")
	waitFor(t, "moved-in note published", func() bool { return mirror.text(t, vaultID, "out") == "OUT-BODY" })
}

func TestPublishPolicy_Normalize(t *testing.T) {
	ok := []struct{ in, want string }{
		{"", PublishScopeFlagged}, {"flagged", "flagged"}, {"all", "all"},
		{"folder:blog", "folder:blog"}, {"folder:/blog/posts/", "folder:blog/posts"},
	}
	for _, c := range ok {
		p, err := PublishPolicy{Allowed: true, Scope: c.in}.Normalize()
		if err != nil || p.Scope != c.want {
			t.Fatalf("%q: %+v %v", c.in, p, err)
		}
	}
	for _, bad := range []string{"folder:", "folder:../x", "folder:a/../b", "folder:.hidden", "every", "folder:a\\b"} {
		if _, err := (PublishPolicy{Allowed: true, Scope: bad}).Normalize(); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("%q accepted", bad)
		}
	}
	if _, err := (PublishPolicy{Scope: "all"}).Normalize(); !errors.Is(err, domain.ErrValidation) {
		t.Fatal("allowed=false accepted")
	}
	p := PublishPolicy{Allowed: true, Scope: "folder:blog"}
	if !p.Match("blog/a.md", nil) || p.Match("blogger/a.md", nil) || p.Match("blog.md", nil) {
		t.Fatal("folder match")
	}
	f := PublishPolicy{Allowed: true, Scope: PublishScopeFlagged}
	if !f.Match("a.md", []byte(`{"publish":true}`)) || f.Match("a.md", []byte(`{"publish":"true"}`)) || f.Match("a.md", nil) {
		t.Fatal("flagged match")
	}
}

func TestMinimizeControl_KeepsOnlyThePublishServersMembers(t *testing.T) {
	doc := ControlState{V: 1, VaultID: uuid.New(), Seq: 9, Name: "Book",
		Roles: []ControlRole{{Name: "Viewer", Capabilities: []string{"note.read"}}},
		Members: []ControlMember{
			{Key: "alice@https://home.example", Role: "Admin"},
			{Key: "bob@https://pub.example", Role: "Viewer"},
			{Key: "carol@https://other.example", Role: "Editor"},
		}}
	raw, _ := json.Marshal(doc)
	out, err := MinimizeControl(raw, "https://pub.example/")
	if err != nil {
		t.Fatal(err)
	}
	var got ControlState
	_ = json.Unmarshal(out, &got)
	if got.Seq != 9 || got.Name != "Book" || len(got.Roles) != 1 || len(got.Members) != 1 || got.Members[0].Key != "bob@https://pub.example" {
		t.Fatalf("minimised = %+v", got)
	}
	if bytes.Contains(out, []byte("alice")) || bytes.Contains(out, []byte("carol")) {
		t.Fatal("other members leaked")
	}
}
