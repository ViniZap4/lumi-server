package publish

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/federation"
)

type fakeSettings map[string]domain.PublishSetting

func (f fakeSettings) GetByBasePath(_ context.Context, p string) (domain.PublishSetting, error) {
	if s, ok := f[p]; ok {
		return s, nil
	}
	return domain.PublishSetting{}, domain.ErrNotFound
}

type fakeLinks map[uuid.UUID][]domain.Federation

func (f fakeLinks) ListForVault(_ context.Context, id uuid.UUID) ([]domain.Federation, error) {
	return f[id], nil
}

type fakeVaults map[uuid.UUID]domain.Vault

func (f fakeVaults) GetByID(_ context.Context, id uuid.UUID) (domain.Vault, error) {
	if v, ok := f[id]; ok {
		return v, nil
	}
	return domain.Vault{}, domain.ErrNotFound
}

type fakeNote struct {
	n     domain.Note
	front map[string]any
	body  string
}

type fakeNotes map[string]fakeNote

func (f fakeNotes) List(_ context.Context, vaultID uuid.UUID, limit, offset int) ([]domain.Note, error) {
	var out []domain.Note
	for _, x := range f {
		if x.n.VaultID == vaultID {
			out = append(out, x.n)
		}
	}
	if offset >= len(out) {
		return nil, nil
	}
	return out[offset:min(len(out), offset+limit)], nil
}

func (f fakeNotes) GetContent(_ context.Context, vaultID uuid.UUID, id string) (domain.Note, map[string]any, []byte, error) {
	x, ok := f[id]
	if !ok || x.n.VaultID != vaultID {
		return domain.Note{}, nil, nil, domain.ErrNotFound
	}
	return x.n, x.front, []byte(x.body), nil
}

type fixture struct {
	app   *fiber.App
	links fakeLinks
	vault uuid.UUID
	set   fakeSettings
	svc   *Service
}

func policyJSON(p federation.PublishPolicy) []byte { return federation.MarshalPublish(&p) }

func newFixture(t *testing.T) *fixture {
	t.Helper()
	vid := uuid.New()
	now := time.Now()
	note := func(id, path, title, body string, front map[string]any) fakeNote {
		return fakeNote{n: domain.Note{ID: id, VaultID: vid, Path: path, Title: title, UpdatedAt: now}, front: front, body: body}
	}
	notes := fakeNotes{
		"hello":   note("hello", "hello.md", "Hello world", "# Hi\npublic text", map[string]any{"publish": true, "tags": []any{"x"}}),
		"diary":   note("diary", "private/diary.md", "My secret diary", "SECRET BODY", map[string]any{"tags": []any{"private"}}),
		"strflag": note("strflag", "strflag.md", "String flag", "STRING FLAG BODY", map[string]any{"publish": "true"}),
		"board":   note("board", "board.canvas", "Board", `{"nodes":[]}`, map[string]any{}),
	}
	f := &fixture{
		vault: vid,
		set:   fakeSettings{"/p/blog": {VaultID: vid, BasePath: "/p/blog", Robots: "noindex"}},
		links: fakeLinks{vid: {{
			VaultID: vid, Role: "follower", Mode: federation.ModeMirror, Status: "active",
			PeerURL: "https://home.example",
			Publish: policyJSON(federation.PublishPolicy{Allowed: true, Scope: federation.PublishScopeFlagged}),
		}}},
	}
	f.svc = &Service{Enabled: true, Settings: f.set, Links: f.links,
		Vaults: fakeVaults{vid: {ID: vid, Name: "Public book", Slug: "blog"}}, Notes: notes}
	f.app = fiber.New()
	h := NewHandlers(f.svc)
	h.ClientIP = func(c *fiber.Ctx) string { return c.Get("X-Test-IP") }
	h.Register(f.app)
	return f
}

type resp struct {
	status int
	header map[string]string
	body   string
}

func (f *fixture) get(t *testing.T, path string, ip ...string) resp {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	if len(ip) > 0 {
		req.Header.Set("X-Test-IP", ip[0])
	}
	r, err := f.app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	h := map[string]string{}
	for _, k := range []string{"Cache-Control", "X-Robots-Tag", "Set-Cookie", "Retry-After", "Content-Security-Policy"} {
		h[k] = r.Header.Get(k)
	}
	return resp{r.StatusCode, h, string(b)}
}

var secrets = []string{"diary", "My secret diary", "SECRET", "private", "strflag", "STRING FLAG", "board", "home.example"}

func noSecrets(t *testing.T, where, body string) {
	t.Helper()
	for _, s := range secrets {
		if strings.Contains(body, s) {
			t.Fatalf("%s leaked %q: %s", where, s, body)
		}
	}
}

func TestPublic_ListsOnlyPublishedNotes(t *testing.T) {
	f := newFixture(t)
	r := f.get(t, "/api/public/books/blog")
	if r.status != 200 {
		t.Fatalf("%d %s", r.status, r.body)
	}
	var out struct {
		Name  string        `json:"name"`
		Notes []NoteSummary `json:"notes"`
	}
	if err := json.Unmarshal([]byte(r.body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Name != "Public book" || len(out.Notes) != 1 || out.Notes[0].ID != "hello" || out.Notes[0].Kind != "markdown" {
		t.Fatalf("listing = %+v", out)
	}
	noSecrets(t, "listing", r.body)
	if strings.Contains(r.body, "tags") || strings.Contains(r.body, "members") {
		t.Fatalf("listing carries more than the contract: %s", r.body)
	}
	if r.header["Cache-Control"] != "public, max-age=60" || r.header["X-Robots-Tag"] != "noindex, nofollow" ||
		r.header["Set-Cookie"] != "" || !strings.Contains(r.header["Content-Security-Policy"], "sandbox") {
		t.Fatalf("headers %+v", r.header)
	}
}

func TestPublic_NoteBodyAndUniformRefusals(t *testing.T) {
	f := newFixture(t)
	r := f.get(t, "/api/public/books/blog/notes/hello")
	if r.status != 200 || !strings.Contains(r.body, "public text") || strings.Contains(r.body, "tags") {
		t.Fatalf("published note: %d %s", r.status, r.body)
	}
	unknown := f.get(t, "/api/public/books/blog/notes/nope")
	if unknown.status != 404 {
		t.Fatalf("unknown: %d", unknown.status)
	}
	// Unpublished, string-flagged and canvas notes are indistinguishable
	// from an id that does not exist.
	for _, id := range []string{"diary", "strflag", "board", "..%2Fdiary"} {
		r := f.get(t, "/api/public/books/blog/notes/"+id)
		if r.status != 404 || r.body != unknown.body {
			t.Fatalf("%s: %d %s (unknown answers %s)", id, r.status, r.body, unknown.body)
		}
		noSecrets(t, id, r.body)
	}
	// Unknown book, same body.
	if r := f.get(t, "/api/public/books/nope"); r.status != 404 || r.body != unknown.body {
		t.Fatalf("unknown book: %d %s", r.status, r.body)
	}
}

func TestPublic_GatesAndGone(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(f *fixture)
		want   int
	}{
		{"publishing disabled on this server", func(f *fixture) { f.svc.Enabled = false }, 404},
		{"no owner consent on the link", func(f *fixture) { f.links[f.vault][0].Publish = nil }, 404},
		{"unreadable policy", func(f *fixture) { f.links[f.vault][0].Publish = []byte(`{"allowed":false}`) }, 404},
		{"replica link", func(f *fixture) { f.links[f.vault][0].Mode = federation.ModeReplica }, 404},
		{"promoted", func(f *fixture) { now := time.Now(); f.links[f.vault][0].PromotedAt = &now }, 404},
		{"severed, not purged", func(f *fixture) { f.links[f.vault][0].Status = "severed" }, 410},
		{"no operator opt-in", func(f *fixture) { delete(f.set, "/p/blog") }, 404},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			tc.mutate(f)
			for _, p := range []string{"/api/public/books/blog", "/api/public/books/blog/notes/hello"} {
				r := f.get(t, p)
				if r.status != tc.want {
					t.Fatalf("%s: %d %s", p, r.status, r.body)
				}
				noSecrets(t, p, r.body)
				if strings.Contains(r.body, "public text") || strings.Contains(r.body, "Hello world") {
					t.Fatalf("%s served content: %s", p, r.body)
				}
			}
		})
	}
}

func TestPublic_IndexingNeedsOwnerAndOperator(t *testing.T) {
	f := newFixture(t)
	f.links[f.vault][0].Publish = policyJSON(federation.PublishPolicy{Allowed: true, Scope: "all", Index: true})
	if r := f.get(t, "/api/public/books/blog"); r.header["X-Robots-Tag"] != "noindex, nofollow" {
		t.Fatalf("operator said noindex: %q", r.header["X-Robots-Tag"])
	}
	s := f.set["/p/blog"]
	s.Robots = "index"
	f.set["/p/blog"] = s
	if r := f.get(t, "/api/public/books/blog"); r.header["X-Robots-Tag"] != "" {
		t.Fatalf("both allow indexing: %q", r.header["X-Robots-Tag"])
	}
	// Scope "all" serves every note, canvas included.
	if r := f.get(t, "/api/public/books/blog/notes/board"); r.status != 200 || !strings.Contains(r.body, `"kind":"canvas"`) {
		t.Fatalf("canvas under all: %d %s", r.status, r.body)
	}
}

func TestPublic_RateLimitPerIP(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < PerIPPerMinute; i++ {
		if r := f.get(t, "/api/public/books/blog", "198.51.100.1"); r.status != 200 {
			t.Fatalf("request %d: %d", i, r.status)
		}
	}
	r := f.get(t, "/api/public/books/blog", "198.51.100.1")
	if r.status != 429 || r.header["Retry-After"] == "" {
		t.Fatalf("over the limit: %d %+v", r.status, r.header)
	}
	if r := f.get(t, "/api/public/books/blog", "198.51.100.2"); r.status != 200 {
		t.Fatalf("other ip: %d", r.status)
	}
	// Unknown slugs count against the IP too (no free enumeration).
	if r := f.get(t, "/api/public/books/zzz", "198.51.100.1"); r.status != 429 {
		t.Fatalf("enumeration while limited: %d", r.status)
	}
}

func TestWindowLimiter(t *testing.T) {
	l := newWindowLimiter(2, time.Minute)
	t0 := time.Unix(1000, 0)
	if ok, _ := l.allow("k", t0); !ok {
		t.Fatal()
	}
	if ok, _ := l.allow("k", t0); !ok {
		t.Fatal()
	}
	if ok, wait := l.allow("k", t0.Add(10*time.Second)); ok || wait != 50*time.Second {
		t.Fatalf("third: %v %v", ok, wait)
	}
	if ok, _ := l.allow("k", t0.Add(time.Minute)); !ok {
		t.Fatal("next window")
	}
}
