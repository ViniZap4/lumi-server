package notes

// Benchmarks for the notes listing endpoints (docs/PERF-BUDGETS.md,
// umbrella: REST p99 list <= 30 ms at 200 rows, /changes <= 20 ms).
// The repo returns precomputed pages, so these measure what the server
// owns on top of SQL: routing, capability check, DTO mapping and JSON.
// SQL itself is covered by the integration load test.
//
//   GOTOOLCHAIN=go1.26.11 go test -run '^$' -bench . -benchmem ./internal/notes

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/capguard"
	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/storage/fs"
)

// pagedRepo serves fixed pages: the cost under test is the handler's.
type pagedRepo struct {
	*fakeNoteRepo
	page    []domain.Note
	changes domain.NoteChanges
}

func (p *pagedRepo) ListForVault(_ context.Context, _ uuid.UUID, limit, offset int) ([]domain.Note, error) {
	end := min(offset+limit, len(p.page))
	if offset >= end {
		return nil, nil
	}
	return p.page[offset:end], nil
}

func (p *pagedRepo) Changes(context.Context, uuid.UUID, int64, int) (domain.NoteChanges, error) {
	return p.changes, nil
}

func benchNotes(vault uuid.UUID, n int) []domain.Note {
	at := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)
	out := make([]domain.Note, n)
	for i := range out {
		out[i] = domain.Note{
			ID:        fmt.Sprintf("note-%05d", i),
			VaultID:   vault,
			Path:      fmt.Sprintf("pasta-%02d/subpasta-%02d/note-%05d.md", i%40, i%7, i),
			Title:     fmt.Sprintf("Nota de trabalho número %d", i),
			CreatedAt: at.Add(-time.Duration(i) * time.Minute),
			UpdatedAt: at,
			ChangeSeq: int64(i + 1),
			CRDTEpoch: "01JDBENCHEPOCH0000000000000",
		}
	}
	return out
}

func benchApp(b *testing.B, rows int) (*fiber.App, uuid.UUID, uuid.UUID) {
	b.Helper()
	mgr, err := fs.NewManager(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	vault := domain.Vault{ID: uuid.New(), Slug: "v"}
	notes := benchNotes(vault.ID, rows)
	repo := &pagedRepo{
		fakeNoteRepo: &fakeNoteRepo{byVault: map[uuid.UUID][]domain.Note{}},
		page:         notes,
		changes:      domain.NoteChanges{Notes: notes, Head: int64(rows)},
	}
	svc := NewService(repo, &fakeVaultLookup{byID: map[uuid.UUID]domain.Vault{vault.ID: vault}}, mgr, nil, fakeCopyResolver{}, nil, nil)
	user := uuid.New()
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		capguard.SetUserID(c, user)
		return c.Next()
	})
	NewHandlers(svc).Register(app.Group("/api"))
	return app, vault.ID, user
}

func benchGet(b *testing.B, app *fiber.App, url string) {
	b.Helper()
	b.ReportAllocs()
	b.ResetTimer()
	var bytes int64
	for i := 0; i < b.N; i++ {
		resp, err := app.Test(httptest.NewRequest(http.MethodGet, url, nil), -1)
		if err != nil {
			b.Fatal(err)
		}
		n, _ := io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b.Fatalf("GET %s: %d", url, resp.StatusCode)
		}
		bytes = n
	}
	b.StopTimer()
	b.ReportMetric(float64(bytes), "resp-bytes")
}

// BenchmarkListNotes: GET /api/vaults/:vault/notes, one 200-row page.
func BenchmarkListNotes(b *testing.B) {
	app, vault, _ := benchApp(b, maxLimit)
	benchGet(b, app, fmt.Sprintf("/api/vaults/%s/notes?limit=%d", vault, maxLimit))
}

// BenchmarkChanges: GET /api/vaults/:vault/changes, one full page
// (the catch-up a client runs after a vault.head event on a big book).
func BenchmarkChanges(b *testing.B) {
	app, vault, _ := benchApp(b, maxChangesLimit)
	benchGet(b, app, fmt.Sprintf("/api/vaults/%s/changes?after=0&limit=%d", vault, maxChangesLimit))
}
