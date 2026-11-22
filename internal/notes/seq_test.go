package notes

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/capguard"
	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/storage/fs"
)

type headRec struct {
	mu   sync.Mutex
	seqs map[uuid.UUID][]int64
}

func (h *headRec) VaultHead(v uuid.UUID, seq int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.seqs == nil {
		h.seqs = map[uuid.UUID][]int64{}
	}
	h.seqs[v] = append(h.seqs[v], seq)
}

func (h *headRec) of(v uuid.UUID) []int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]int64(nil), h.seqs[v]...)
}

type seqFixture struct {
	svc   *Service
	repo  *fakeNoteRepo
	heads *headRec
	vault domain.Vault
	other domain.Vault
}

func newSeqFixture(t *testing.T) *seqFixture {
	t.Helper()
	mgr, err := fs.NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	vault := domain.Vault{ID: uuid.New(), Slug: "v"}
	other := domain.Vault{ID: uuid.New(), Slug: "o"}
	for _, v := range []domain.Vault{vault, other} {
		if _, err := mgr.EnsureVaultDir(v.Slug); err != nil {
			t.Fatal(err)
		}
	}
	repo := &fakeNoteRepo{byVault: map[uuid.UUID][]domain.Note{}}
	svc := NewService(repo,
		&fakeVaultLookup{byID: map[uuid.UUID]domain.Vault{vault.ID: vault, other.ID: other}},
		mgr, nil, fakeCopyResolver{}, nil, nil)
	heads := &headRec{}
	svc.SetHeadPublisher(heads)
	return &seqFixture{svc: svc, repo: repo, heads: heads, vault: vault, other: other}
}

func strictlyIncreasing(s []int64) bool {
	for i := 1; i < len(s); i++ {
		if s[i] <= s[i-1] {
			return false
		}
	}
	return true
}

// Every metadata write path bumps the vault seq and publishes it.
func TestSeq_EveryMetadataWriteBumpsAndPublishes(t *testing.T) {
	f := newSeqFixture(t)
	ctx := context.Background()
	v := f.vault.ID

	n, err := f.svc.Create(ctx, v, CreateInput{Title: "Hello", Body: "b"})
	if err != nil {
		t.Fatal(err)
	}
	title := "Hello 2"
	if _, err := f.svc.Update(ctx, v, n.ID, UpdateInput{Title: &title}); err != nil {
		t.Fatal(err)
	}
	path := "sub/hello.md"
	if _, err := f.svc.Update(ctx, v, n.ID, UpdateInput{Path: &path}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.MoveFromFederation(ctx, v, n.ID, "hello.md", "Hello 3"); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.CreateFromFederation(ctx, domain.Note{ID: "remote", VaultID: v, Path: "remote.md", Title: "R"}); err != nil {
		t.Fatal(err)
	}
	// Idempotent: a second announcement of the same note does not bump.
	if err := f.svc.CreateFromFederation(ctx, domain.Note{ID: "remote", VaultID: v, Path: "remote.md", Title: "R"}); err != nil {
		t.Fatal(err)
	}
	f.svc.BumpContent(ctx, v, n.ID)
	if err := f.svc.Delete(ctx, v, n.ID, uuid.Nil, "", ""); err != nil {
		t.Fatal(err)
	}
	f.svc.BumpContent(ctx, v, n.ID) // deleted meanwhile: ignored

	got := f.heads.of(v)
	want := []int64{1, 2, 3, 4, 5, 6, 7}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("published heads %v, want %v", got, want)
	}
	if h := f.repo.heads[v]; h != 7 {
		t.Fatalf("repo head %d, want 7", h)
	}
	if len(f.heads.of(f.other.ID)) != 0 {
		t.Fatal("writes leaked heads into another vault")
	}
}

// A no-op PATCH does not bump.
func TestSeq_NoOpUpdateDoesNotBump(t *testing.T) {
	f := newSeqFixture(t)
	ctx := context.Background()
	n, err := f.svc.Create(ctx, f.vault.ID, CreateInput{Title: "Same"})
	if err != nil {
		t.Fatal(err)
	}
	title := "Same"
	if _, err := f.svc.Update(ctx, f.vault.ID, n.ID, UpdateInput{Title: &title}); err != nil {
		t.Fatal(err)
	}
	if got := f.heads.of(f.vault.ID); len(got) != 1 {
		t.Fatalf("heads %v, want only the create", got)
	}
}

// S1: 50 concurrent writers in one vault get 50 distinct seqs 1..50, and
// the head ends at 50. (The real serialisation is the vault_heads row
// lock; the fake models it with a mutex — see pg.TestNoteStore_SQLContract
// for the statement-level guard.)
func TestSeq_ConcurrentWritesGetUniqueSeqs(t *testing.T) {
	f := newSeqFixture(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make(chan error, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Distinct titles so allocateNoteID never collides.
			if _, err := f.svc.Create(ctx, f.vault.ID, CreateInput{Title: fmt.Sprintf("note %d", i)}); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	got := f.heads.of(f.vault.ID)
	sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
	if len(got) != 50 || got[0] != 1 || got[49] != 50 || !strictlyIncreasing(got) {
		t.Fatalf("seqs %v, want exactly 1..50", got)
	}
	seen := map[int64]bool{}
	for _, n := range f.repo.byVault[f.vault.ID] {
		if seen[n.ChangeSeq] {
			t.Fatalf("change_seq %d stamped twice", n.ChangeSeq)
		}
		seen[n.ChangeSeq] = true
	}
}

// ---- GET /changes --------------------------------------------------------------

// memberResolver grants note.read to the listed (vault,user) pairs only.
type memberResolver map[[2]uuid.UUID]bool

func (m memberResolver) RoleForUser(_ context.Context, v, u uuid.UUID) (domain.Role, error) {
	if m[[2]uuid.UUID{v, u}] {
		return domain.Role{Name: "Viewer", Capabilities: domain.CapabilitySet{domain.CapNoteRead}}, nil
	}
	return domain.Role{}, domain.ErrNotFound
}

type changesResp struct {
	Notes []struct {
		ID        string `json:"id"`
		ChangeSeq int64  `json:"change_seq"`
		VaultID   string `json:"vault_id"`
	} `json:"notes"`
	Deleted []struct {
		ID  string `json:"id"`
		Seq int64  `json:"seq"`
	} `json:"deleted"`
	Head  int64  `json:"head"`
	More  bool   `json:"more"`
	Error string `json:"error"`
}

func changesApp(f *seqFixture, res memberResolver) *fiber.App {
	f.svc.resolver = res
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

func getChanges(t *testing.T, app *fiber.App, user uuid.UUID, vault uuid.UUID, query string) (int, changesResp) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/vaults/"+vault.String()+"/changes"+query, nil)
	req.Header.Set("X-Test-User", user.String())
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	var out changesResp
	_ = json.Unmarshal(body, &out)
	return resp.StatusCode, out
}

// S1: paging through the log with a small limit visits every change in seq
// order exactly once (no gaps, no repeats), deletions included, and ends
// with cursor == head.
func TestChanges_PaginatesWithoutGaps(t *testing.T) {
	f := newSeqFixture(t)
	ctx := context.Background()
	user := uuid.New()
	app := changesApp(f, memberResolver{{f.vault.ID, user}: true})

	var ids []string
	for i := 0; i < 8; i++ {
		n, err := f.svc.Create(ctx, f.vault.ID, CreateInput{Title: fmt.Sprintf("n%d", i)})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, n.ID)
	}
	_ = f.svc.Delete(ctx, f.vault.ID, ids[1], uuid.Nil, "", "") // seq 9
	t2 := "renamed"
	_, _ = f.svc.Update(ctx, f.vault.ID, ids[0], UpdateInput{Title: &t2}) // seq 10
	_ = f.svc.Delete(ctx, f.vault.ID, ids[2], uuid.Nil, "", "")           // seq 11

	// Expected log: live notes at their latest seq + tombstones.
	var cursor int64
	var seqs []int64
	for pages := 0; pages < 20; pages++ {
		code, page := getChanges(t, app, user, f.vault.ID, fmt.Sprintf("?after=%d&limit=3", cursor))
		if code != http.StatusOK {
			t.Fatalf("status %d", code)
		}
		if page.Head != 11 {
			t.Fatalf("head %d, want 11", page.Head)
		}
		if len(page.Notes)+len(page.Deleted) > 3 {
			t.Fatalf("page exceeds limit: %+v", page)
		}
		for _, n := range page.Notes {
			seqs = append(seqs, n.ChangeSeq)
			if n.VaultID != f.vault.ID.String() {
				t.Fatalf("note from another vault: %+v", n)
			}
		}
		for _, d := range page.Deleted {
			seqs = append(seqs, d.Seq)
		}
		if !page.More {
			cursor = page.Head
			break
		}
		for _, s := range seqs {
			cursor = max(cursor, s)
		}
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	// ids[0] moved from 1 to 10; ids[1] and ids[2] are tombstones 9, 11.
	want := []int64{4, 5, 6, 7, 8, 9, 10, 11}
	if fmt.Sprint(seqs) != fmt.Sprint(want) {
		t.Fatalf("visited seqs %v, want %v", seqs, want)
	}
	if cursor != 11 {
		t.Fatalf("final cursor %d", cursor)
	}

	// Caught up: nothing new, more=false.
	code, page := getChanges(t, app, user, f.vault.ID, "?after=11")
	if code != http.StatusOK || len(page.Notes) != 0 || len(page.Deleted) != 0 || page.More {
		t.Fatalf("caught-up page: %d %+v", code, page)
	}
}

// S1: a cursor below the tombstone floor answers 410 with the head;
// after=0 (full listing) and cursors at/above the floor still work.
func TestChanges_BelowFloorIs410(t *testing.T) {
	f := newSeqFixture(t)
	ctx := context.Background()
	user := uuid.New()
	app := changesApp(f, memberResolver{{f.vault.ID, user}: true})
	for i := 0; i < 4; i++ {
		n, _ := f.svc.Create(ctx, f.vault.ID, CreateInput{Title: fmt.Sprintf("n%d", i)})
		_ = f.svc.Delete(ctx, f.vault.ID, n.ID, uuid.Nil, "", "")
	}
	f.repo.prune(f.vault.ID, 6) // tombstones 2,4,6 gone; floor 6

	code, page := getChanges(t, app, user, f.vault.ID, "?after=3")
	if code != http.StatusGone || page.Error != "resync_required" || page.Head != 8 {
		t.Fatalf("below floor: %d %+v", code, page)
	}
	if code, _ := getChanges(t, app, user, f.vault.ID, "?after=0"); code != http.StatusOK {
		t.Fatalf("after=0 must never 410, got %d", code)
	}
	code, page = getChanges(t, app, user, f.vault.ID, "?after=6")
	if code != http.StatusOK || len(page.Deleted) != 1 || page.Deleted[0].Seq != 8 {
		t.Fatalf("at floor: %d %+v", code, page)
	}
}

// Authorization: another account's token cannot read the log, and bad
// parameters are rejected.
func TestChanges_AuthAndValidation(t *testing.T) {
	f := newSeqFixture(t)
	owner, stranger := uuid.New(), uuid.New()
	app := changesApp(f, memberResolver{{f.vault.ID, owner}: true})
	if _, err := f.svc.Create(context.Background(), f.vault.ID, CreateInput{Title: "secret"}); err != nil {
		t.Fatal(err)
	}
	if code, page := getChanges(t, app, stranger, f.vault.ID, ""); code != http.StatusForbidden || len(page.Notes) != 0 {
		t.Fatalf("stranger: %d %+v", code, page)
	}
	for _, q := range []string{"?after=-1", "?after=x", "?limit=0", "?limit=abc"} {
		if code, _ := getChanges(t, app, owner, f.vault.ID, q); code != http.StatusBadRequest {
			t.Fatalf("%s: status %d, want 400", q, code)
		}
	}
	if code, page := getChanges(t, app, owner, f.vault.ID, "?limit=5000"); code != http.StatusOK || len(page.Notes) != 1 {
		t.Fatalf("limit clamp: %d %+v", code, page)
	}
}
