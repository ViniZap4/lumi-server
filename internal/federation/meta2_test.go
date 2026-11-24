package federation

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestFrameCodec_Meta2AndProto(t *testing.T) {
	f, err := DecodeFrame(EncodeNoteMeta2(NoteMeta{ID: "a", Path: "a.md", Title: "A"}, []byte(`{"tags":["x"]}`)))
	if err != nil || f.Type != frameNoteMeta2 || f.Note.ID != "a" || string(f.Payload) != `{"tags":["x"]}` {
		t.Fatalf("meta2 round-trip: %+v %v", f, err)
	}
	big := []byte(`{"k":"` + strings.Repeat("x", maxFrontmatterBytes) + `"}`)
	if _, err := DecodeFrame(EncodeNoteMeta2(NoteMeta{ID: "a", Path: "a.md"}, big)); err == nil {
		t.Fatal("oversized frontmatter accepted")
	}
	// A v2 manifest advertises the protocol after the epoch list...
	f, err = DecodeFrame(EncodeManifest([]NoteMeta{{ID: "a", Path: "a.md", Title: "A", Epoch: "e1"}}))
	if err != nil || f.Proto != RelayProtoVersion || f.Manifest[0].Epoch != "e1" {
		t.Fatalf("v2 manifest: %+v %v", f, err)
	}
	// ...which a v1 manifest (epochs, nothing after) lacks.
	v1 := writeVarUint(nil, frameManifest)
	v1 = writeVarUint(v1, 1)
	v1 = appendNoteMeta(v1, NoteMeta{ID: "a", Path: "a.md", Title: "A"})
	v1 = writeVarUint(v1, 1)
	v1 = writeVarBytes(v1, []byte("e1"))
	if f, err := DecodeFrame(v1); err != nil || f.Proto != 1 || f.Manifest[0].Epoch != "e1" {
		t.Fatalf("v1 manifest: %+v %v", f, err)
	}
	for _, typ := range []uint64{frameMirrorAck, frameChangesEnd, frameResumeFrom} {
		f, err := DecodeFrame(encodeSeqFrame(typ, 42))
		if err != nil || f.Type != typ || f.Seq != 42 {
			t.Fatalf("seq frame %d: %+v %v", typ, f, err)
		}
	}
}

type fmStore struct {
	mu      sync.Mutex
	docs    map[string]string // note -> frontmatter JSON served
	applied map[string]string // note -> last applied JSON
}

func newFMStore() *fmStore {
	return &fmStore{docs: map[string]string{}, applied: map[string]string{}}
}

func (s *fmStore) read(_ context.Context, _ uuid.UUID, id string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.docs[id]; ok {
		return []byte(d), nil
	}
	return nil, nil
}

func (s *fmStore) apply(_ context.Context, _ uuid.UUID, id string, fm []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.applied[id] = string(fm)
	s.docs[id] = string(fm)
	return nil
}

func (s *fmStore) got(id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.applied[id]
}

func withFM(rs *relaySide) *fmStore {
	st := newFMStore()
	rs.links.deps.Frontmatter = st.read
	rs.links.deps.ApplyFrontmatter = st.apply
	return st
}

// G1: frontmatter reaches a v2 follower at link-up, on creation and on
// change; a follower edit flows back to home and on to other links.
func TestRelay_FrontmatterReplicates(t *testing.T) {
	vaultID := uuid.New()
	home, follower := newRelaySide(t), newRelaySide(t)
	hfm, ffm := withFM(home), withFM(follower)
	home.seedEpoch(t, vaultID, "alpha", "text", "e1")
	hfm.docs["alpha"] = `{"created_at":"2020-01-02T03:04:05Z","tags":["a"]}`

	homeConn, followerConn := newPipePair()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hs := home.links.NewSessionWith(ctx, homeConn, vaultID, "https://follower.example", "home", SessionOptions{PeerProto: 2})
	fs := follower.links.NewSession(ctx, followerConn, vaultID, "https://home.example", "follower")
	go func() { _ = hs.Run() }()
	go func() { _ = fs.Run() }()

	waitFor(t, "opening frontmatter", func() bool { return ffm.got("alpha") == hfm.docs["alpha"] })

	home.seedEpoch(t, vaultID, "beta", "b", "e2")
	hfm.mu.Lock()
	hfm.docs["beta"] = `{"tags":["new"]}`
	hfm.mu.Unlock()
	home.links.NoteCreated(vaultID, "beta", "beta.md", "beta")
	waitFor(t, "frontmatter of a created note", func() bool { return ffm.got("beta") == `{"tags":["new"]}` })

	hfm.mu.Lock()
	hfm.docs["alpha"] = `{"tags":["a","b"]}`
	hfm.mu.Unlock()
	home.links.NoteMetaChanged(vaultID, "alpha")
	waitFor(t, "tag change", func() bool { return ffm.got("alpha") == `{"tags":["a","b"]}` })

	// The follower learned home speaks v2 from the manifest: its own
	// change goes back to home.
	ffm.mu.Lock()
	ffm.docs["alpha"] = `{"tags":["from follower"]}`
	ffm.mu.Unlock()
	follower.links.NoteMetaChanged(vaultID, "alpha")
	waitFor(t, "follower tag change at home", func() bool { return hfm.got("alpha") == `{"tags":["from follower"]}` })
}

// A v1 follower (no proto query) never receives frame 11, which its
// decoder would reject and drop the link over.
func TestRelay_NoMeta2ToV1Peers(t *testing.T) {
	vaultID := uuid.New()
	home := newRelaySide(t)
	hfm := withFM(home)
	home.seedEpoch(t, vaultID, "alpha", "text", "e1")
	hfm.docs["alpha"] = `{"tags":["a"]}`

	homeConn, peer := newPipePair()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hs := home.links.NewSession(ctx, homeConn, vaultID, "https://old.example", "home")
	go func() { _ = hs.Run() }()
	home.links.NoteMetaChanged(vaultID, "alpha")

	deadline := time.After(500 * time.Millisecond)
	for {
		select {
		case msg := <-peer.in:
			typ, _, _ := readVarUint(msg)
			if typ > frameNoteMove {
				t.Fatalf("v1 peer got frame type %d", typ)
			}
		case <-deadline:
			return
		}
	}
}
