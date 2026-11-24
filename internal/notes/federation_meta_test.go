package notes

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/storage/fs"
)

type metaFixture struct {
	svc   *Service
	mgr   *fs.Manager
	repo  *fakeNoteRepo
	vault uuid.UUID
}

func newMetaFixture(t *testing.T) *metaFixture {
	t.Helper()
	mgr, err := fs.NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	vid := uuid.New()
	if _, err := mgr.EnsureVaultDir("book"); err != nil {
		t.Fatal(err)
	}
	repo := &fakeNoteRepo{byVault: map[uuid.UUID][]domain.Note{}}
	lookup := &fakeVaultLookup{byID: map[uuid.UUID]domain.Vault{vid: {ID: vid, Slug: "book"}}}
	svc := NewService(repo, lookup, mgr, nil, fakeCopyResolver{}, nil, nil)
	return &metaFixture{svc: svc, mgr: mgr, repo: repo, vault: vid}
}

func (f *metaFixture) row(t *testing.T, id, path string) domain.Note {
	t.Helper()
	n := domain.Note{ID: id, VaultID: f.vault, Path: path, Title: "T " + id, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if _, err := f.repo.Upsert(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	return n
}

// G1: what home reads is exactly the replicated keys, and what a peer
// writes reproduces them, keeping its own derived keys and the body.
func TestFrontmatterReplicationRoundTrip(t *testing.T) {
	home, peer := newMetaFixture(t), newMetaFixture(t)
	ctx := context.Background()
	home.row(t, "alpha", "alpha.md")
	if err := home.mgr.WriteNote("book", "alpha.md", map[string]any{
		"id": "alpha", "title": "Alpha", "updated_at": "2026-11-01T10:00:00Z",
		"created_at": "2020-01-02T03:04:05Z", "tags": []any{"work", "lgpd"},
		"custom": map[string]any{"n": 3, "ok": true},
	}, []byte("body\n")); err != nil {
		t.Fatal(err)
	}
	fm, err := home.svc.FrontmatterForFederation(ctx, home.vault, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(fm, &got); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"id", "title", "updated_at"} {
		if _, ok := got[k]; ok {
			t.Fatalf("derived key %q replicated: %s", k, fm)
		}
	}
	if got["created_at"] != "2020-01-02T03:04:05Z" || len(got["tags"].([]any)) != 2 || got["custom"] == nil {
		t.Fatalf("frontmatter = %s", fm)
	}

	// Peer: the note row exists, its content landed with a stale local
	// frontmatter (what WriteBodyFromCRDT used to produce).
	peer.row(t, "alpha", "alpha.md")
	if err := peer.mgr.WriteNote("book", "alpha.md", map[string]any{
		"id": "alpha", "title": "Alpha", "created_at": "2026-11-24T00:00:00Z", "stale": "x",
	}, []byte("body\n")); err != nil {
		t.Fatal(err)
	}
	if err := peer.svc.ApplyFrontmatterFromFederation(ctx, peer.vault, "alpha", fm); err != nil {
		t.Fatal(err)
	}
	front, body, err := peer.mgr.ReadNote("book", "alpha.md")
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "body\n" || front["id"] != "alpha" || front["title"] != "Alpha" {
		t.Fatalf("derived keys/body lost: %v %q", front, body)
	}
	if _, ok := front["stale"]; ok {
		t.Fatalf("key absent at home survived: %v", front)
	}
	tags, _ := front["tags"].([]any)
	if len(tags) != 2 || tags[0] != "work" {
		t.Fatalf("tags = %v", front["tags"])
	}
	again, _ := peer.svc.FrontmatterForFederation(ctx, peer.vault, "alpha")
	var a, b map[string]any
	_ = json.Unmarshal(fm, &a)
	_ = json.Unmarshal(again, &b)
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Fatalf("peer frontmatter %s != home %s", jb, ja)
	}
	n, _ := peer.repo.Get(ctx, peer.vault, "alpha")
	if !n.CreatedAt.Equal(time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Fatalf("row created_at = %v, want home's", n.CreatedAt)
	}

	// Idempotent: applying the same document again writes nothing.
	seq := n.ChangeSeq
	if err := peer.svc.ApplyFrontmatterFromFederation(ctx, peer.vault, "alpha", fm); err != nil {
		t.Fatal(err)
	}
	if n2, _ := peer.repo.Get(ctx, peer.vault, "alpha"); n2.ChangeSeq != seq {
		t.Fatalf("no-op apply bumped seq %d -> %d", seq, n2.ChangeSeq)
	}
}

// Frontmatter that arrives before the content creates the file; canvas
// notes are ignored; malformed documents are refused.
func TestApplyFrontmatterEdgeCases(t *testing.T) {
	f := newMetaFixture(t)
	ctx := context.Background()
	f.row(t, "early", "early.md")
	if err := f.svc.ApplyFrontmatterFromFederation(ctx, f.vault, "early", []byte(`{"tags":["a"]}`)); err != nil {
		t.Fatal(err)
	}
	front, body, err := f.mgr.ReadNote("book", "early.md")
	if err != nil || len(body) != 0 || front["id"] != "early" {
		t.Fatalf("early file: %v %q %v", front, body, err)
	}
	f.row(t, "board.canvas", "board.canvas")
	if err := f.svc.ApplyFrontmatterFromFederation(ctx, f.vault, "board.canvas", []byte(`{"tags":["a"]}`)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.mgr.ReadNote("book", "board.canvas"); err == nil {
		t.Fatal("canvas got a file from frontmatter")
	}
	for _, bad := range []string{`[1,2]`, `"x"`, `null`, `{`} {
		if err := f.svc.ApplyFrontmatterFromFederation(ctx, f.vault, "early", []byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	if fm, err := f.svc.FrontmatterForFederation(ctx, f.vault, "board.canvas"); err != nil || fm != nil {
		t.Fatalf("canvas frontmatter: %s %v", fm, err)
	}
}
