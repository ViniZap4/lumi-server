package notes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/capguard"
	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/wsync"
)

const boardJSON = `{"nodes":[{"id":"n1","type":"text","text":"hi","x":0,"y":0,"width":200,"height":80}],"edges":[]}`

func (f *crdtFixture) rawFile(t *testing.T, rel string) string {
	t.Helper()
	abs, err := f.fsm.NotePath(f.vault.Slug, rel)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(abs)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestCanvas_CreateWritesRawJSONAndDerivesIDAndTitle(t *testing.T) {
	f := newCRDTFixture(t)
	ctx := context.Background()
	n, err := f.svc.Create(ctx, f.vault.ID, CreateInput{Title: "My Board", Body: boardJSON, Kind: domain.NoteKindCanvas})
	if err != nil {
		t.Fatal(err)
	}
	if n.ID != "my-board.canvas" || n.Path != "my-board.canvas" || n.Title != "my-board" {
		t.Fatalf("note = %+v", n)
	}
	if got := f.rawFile(t, n.Path); got != boardJSON {
		t.Fatalf("file = %q, want the raw JSON (no frontmatter)", got)
	}
	if dto := toDTO(n); dto.Kind != "canvas" {
		t.Fatalf("dto kind = %q", dto.Kind)
	}
	snap, err := f.svc.GetSnapshot(ctx, f.vault.ID, n.ID)
	if err != nil || snap.Text != boardJSON {
		t.Fatalf("crdt text = %q err=%v", snap.Text, err)
	}
	_, front, body, err := f.svc.GetContent(ctx, f.vault.ID, n.ID)
	if err != nil || len(front) != 0 || string(body) != boardJSON {
		t.Fatalf("content front=%v body=%q err=%v", front, body, err)
	}

	// An empty body becomes an empty canvas.
	e, err := f.svc.Create(ctx, f.vault.ID, CreateInput{Title: "Empty", Kind: domain.NoteKindCanvas})
	if err != nil {
		t.Fatal(err)
	}
	if got := f.rawFile(t, e.Path); got != EmptyCanvas {
		t.Fatalf("empty canvas file = %q", got)
	}
}

// "a.md" and "a.canvas" get distinct ids; the id spaces never overlap.
func TestCanvas_IDsNeverCollideWithMarkdown(t *testing.T) {
	f := newCRDTFixture(t)
	ctx := context.Background()
	md, err := f.svc.Create(ctx, f.vault.ID, CreateInput{Title: "a", Body: "x"})
	if err != nil {
		t.Fatal(err)
	}
	cv, err := f.svc.Create(ctx, f.vault.ID, CreateInput{Title: "a", Kind: domain.NoteKindCanvas})
	if err != nil {
		t.Fatal(err)
	}
	if md.ID != "a" || md.Path != "a.md" || cv.ID != "a.canvas" || cv.Path != "a.canvas" {
		t.Fatalf("md=%+v canvas=%+v", md, cv)
	}
	cv2, err := f.svc.Create(ctx, f.vault.ID, CreateInput{Title: "a", Kind: domain.NoteKindCanvas})
	if err != nil {
		t.Fatal(err)
	}
	if cv2.ID != "a-2.canvas" || cv2.Path != "a-2.canvas" {
		t.Fatalf("second canvas = %+v", cv2)
	}
	if dto := toDTO(md); dto.Kind != "markdown" {
		t.Fatalf("markdown dto kind = %q", dto.Kind)
	}
}

// A free id does not imply a free path: a note moved onto "hello.md"
// keeps its own id, so the next "Hello" must not overwrite its file.
func TestCreate_SkipsTakenPath(t *testing.T) {
	f := newCRDTFixture(t)
	ctx := context.Background()
	x, err := f.svc.Create(ctx, f.vault.ID, CreateInput{Title: "x", Body: "keep me"})
	if err != nil {
		t.Fatal(err)
	}
	p := "hello.md"
	if _, err := f.svc.Update(ctx, f.vault.ID, x.ID, UpdateInput{Path: &p}); err != nil {
		t.Fatal(err)
	}
	h, err := f.svc.Create(ctx, f.vault.ID, CreateInput{Title: "Hello", Body: "new"})
	if err != nil {
		t.Fatal(err)
	}
	if h.ID != "hello-2" || h.Path != "hello-2.md" {
		t.Fatalf("new note = %+v", h)
	}
	if got := f.diskBody(t, domain.Note{Path: "hello.md"}); got != "keep me" {
		t.Fatalf("moved note body = %q", got)
	}
}

func TestCanvas_CreateValidation(t *testing.T) {
	f := newCRDTFixture(t)
	ctx := context.Background()
	cases := []CreateInput{
		{Title: "bad json", Body: `{"nodes":[`, Kind: domain.NoteKindCanvas},
		{Title: "tags", Body: boardJSON, Kind: domain.NoteKindCanvas, Tags: []string{"x"}},
		{Title: "kind", Body: "x", Kind: "pdf"},
		{Title: "utf8", Body: "\xff\xfe", Kind: domain.NoteKindMarkdown},
		{Title: "big", Body: strings.Repeat("a", domain.MaxNoteBodyBytes+1)},
	}
	for _, in := range cases {
		if _, err := f.svc.Create(ctx, f.vault.ID, in); !errors.Is(err, domain.ErrValidation) {
			t.Errorf("%s: got %v, want ErrValidation", in.Title, err)
		}
	}
}

func TestCanvas_UpdateAndMoveRules(t *testing.T) {
	f := newCRDTFixture(t)
	ctx := context.Background()
	n, err := f.svc.Create(ctx, f.vault.ID, CreateInput{Title: "Plan", Body: boardJSON, Kind: domain.NoteKindCanvas})
	if err != nil {
		t.Fatal(err)
	}
	title := "New"
	if _, err := f.svc.Update(ctx, f.vault.ID, n.ID, UpdateInput{Title: &title}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("title on canvas: %v", err)
	}
	tags := []string{"t"}
	if _, err := f.svc.Update(ctx, f.vault.ID, n.ID, UpdateInput{Tags: &tags}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("tags on canvas: %v", err)
	}
	toMD := "plan.md"
	if _, err := f.svc.Update(ctx, f.vault.ID, n.ID, UpdateInput{Path: &toMD}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("canvas -> md: %v", err)
	}
	md, _ := f.svc.Create(ctx, f.vault.ID, CreateInput{Title: "doc", Body: "x"})
	toCanvas := "doc.canvas"
	if _, err := f.svc.Update(ctx, f.vault.ID, md.ID, UpdateInput{Path: &toCanvas}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("md -> canvas: %v", err)
	}

	// A move keeps the id and takes the title from the new file name.
	dst := "boards/Road Map.canvas"
	moved, err := f.svc.Update(ctx, f.vault.ID, n.ID, UpdateInput{Path: &dst})
	if err != nil {
		t.Fatal(err)
	}
	if moved.ID != n.ID || moved.Path != dst || moved.Title != "Road Map" {
		t.Fatalf("moved = %+v", moved)
	}
	if got := f.rawFile(t, dst); got != boardJSON {
		t.Fatalf("moved file = %q", got)
	}

	// PATCH body replaces the raw text; JSON validity is not enforced
	// (a client may save mid-edit).
	partial := `{"nodes":[`
	if _, err := f.svc.Update(ctx, f.vault.ID, n.ID, UpdateInput{Body: &partial}); err != nil {
		t.Fatal(err)
	}
	if got := f.rawFile(t, dst); got != partial {
		t.Fatalf("patched file = %q", got)
	}

	// Federation moves follow the same rules.
	if err := f.svc.MoveFromFederation(ctx, f.vault.ID, n.ID, "x.md", "x"); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("federation kind change: %v", err)
	}
	if err := f.svc.MoveFromFederation(ctx, f.vault.ID, n.ID, "fed.canvas", "ignored"); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.svc.Get(ctx, f.vault.ID, n.ID); got.Title != "fed" || got.Path != "fed.canvas" {
		t.Fatalf("after federation move = %+v", got)
	}
}

// Live edits (even mid-way through a JSON change) mirror the raw CRDT
// text to disk, never wrapped in frontmatter; an external edit of the
// file diff-merges back the way the FS watcher bridge applies it.
func TestCanvas_LiveMirrorAndExternalEdit(t *testing.T) {
	f := newCRDTFixture(t)
	ctx := context.Background()
	n, err := f.svc.Create(ctx, f.vault.ID, CreateInput{Title: "Live", Body: boardJSON, Kind: domain.NoteKindCanvas})
	if err != nil {
		t.Fatal(err)
	}
	web := f.hub.NewSubscriber(uuid.New())
	room, err := f.hub.Join(ctx, f.vault.ID, n.ID, web)
	if err != nil {
		t.Fatal(err)
	}
	defer f.hub.Leave(room, web)

	mid := strings.Replace(boardJSON, `"hi"`, `"hi there`, 1) // invalid JSON mid-edit
	liveEdit(t, room, web, mid)
	deadline := time.Now().Add(2 * time.Second)
	for f.rawFile(t, n.Path) != mid {
		if time.Now().After(deadline) {
			t.Fatalf("mirror wrote %q, want %q", f.rawFile(t, n.Path), mid)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// External edit (TUI, Obsidian): what the fswatch bridge does.
	ext := strings.Replace(boardJSON, `"hi"`, `"from disk"`, 1)
	abs, _ := f.fsm.NotePath(f.vault.Slug, n.Path)
	if err := os.WriteFile(abs, []byte(ext), 0o644); err != nil {
		t.Fatal(err)
	}
	_, body, err := f.fsm.ReadNote(f.vault.Slug, n.Path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.hub.ApplyText(ctx, f.vault.ID, n.ID, string(body), nil, wsync.ApplyOptions{
		Origin: wsync.OriginFSWatcher, Mirror: wsync.MirrorNone,
	}); err != nil {
		t.Fatal(err)
	}
	if txt, _ := room.Doc().Text(); txt != ext {
		t.Fatalf("room text = %q, want %q", txt, ext)
	}
	expectBroadcast(t, web)
}

func TestCanvas_HTTPKindInCreateListAndChanges(t *testing.T) {
	f := newSeqFixture(t)
	user := uuid.New()
	f.svc.resolver = fakeCopyResolver{} // every capability
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		capguard.SetUserID(c, user)
		return c.Next()
	})
	NewHandlers(f.svc).Register(app.Group("/api"))

	post := func(body string) (int, map[string]any) {
		req := httptest.NewRequest(http.MethodPost, "/api/vaults/"+f.vault.ID.String()+"/notes", bytes.NewBufferString(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Test-User", user.String())
		resp, err := app.Test(req, -1)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		return resp.StatusCode, out
	}
	code, out := post(`{"title":"Board","kind":"canvas"}`)
	if code != http.StatusCreated || out["kind"] != "canvas" || out["id"] != "board.canvas" {
		t.Fatalf("create canvas: %d %v", code, out)
	}
	code, out = post(`{"title":"Doc","body":"x"}`)
	if code != http.StatusCreated || out["kind"] != "markdown" {
		t.Fatalf("create markdown: %d %v", code, out)
	}
	if code, _ = post(`{"title":"Bad","kind":"canvas","body":"{"}`); code != http.StatusBadRequest {
		t.Fatalf("invalid canvas JSON: %d", code)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/vaults/"+f.vault.ID.String()+"/notes", nil)
	req.Header.Set("X-Test-User", user.String())
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	var list struct {
		Notes []struct{ ID, Kind string } `json:"notes"`
	}
	raw, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, n := range list.Notes {
		kinds[n.ID] = n.Kind
	}
	if kinds["board.canvas"] != "canvas" || kinds["doc"] != "markdown" {
		t.Fatalf("list kinds = %v (%s)", kinds, raw)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/vaults/"+f.vault.ID.String()+"/changes", nil)
	req.Header.Set("X-Test-User", user.String())
	resp, err = app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = io.ReadAll(resp.Body)
	var ch struct {
		Notes []struct{ ID, Kind string } `json:"notes"`
	}
	if err := json.Unmarshal(raw, &ch); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range ch.Notes {
		if n.ID == "board.canvas" {
			found = n.Kind == "canvas"
		}
	}
	if !found {
		t.Fatalf("changes missing canvas kind: %s", raw)
	}
}
