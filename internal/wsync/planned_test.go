package wsync

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"unicode/utf16"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/crdt"
)

func TestValidPlannedOrigin(t *testing.T) {
	for _, ok := range []string{"op:web", "op:tui", "op:apple", "op:cli", "ai:mcp", "ai:mac", "ai:server-agent"} {
		if !ValidPlannedOrigin(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", "web", "op:", "ai:", "op:Web", "op:web ui", "federation:https://x", "op:" + strings.Repeat("a", 33), "op:a:b", "OP:web"} {
		if ValidPlannedOrigin(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

// moveFirstLineToEnd is a tiny planner: a card move in an Obsidian Kanban
// list, as two disjoint edits (delete the first line, insert it at end).
func moveFirstLineToEnd(text string) ([]crdt.Edit, error) {
	i := strings.IndexByte(text, '\n')
	if i < 0 {
		return nil, errors.New("no line")
	}
	line := text[:i+1]
	edits, err := crdt.ByteEditsToUTF16(text, []crdt.Edit{{Pos: 0, Del: len(line)}, {Pos: len(text), Ins: line}})
	return edits, err
}

// A planned change is applied under the room lock, persisted with its
// server-derived origin and broadcast to every live subscriber as a
// normal update that a client replica can apply (non-BMP text included).
func TestApplyPlanned_BroadcastsAndPersists(t *testing.T) {
	repo := newMemRepo()
	reg := crdt.NewRegistry(repo)
	hub := NewHub(reg, WithMirrorDebounce(0))
	defer hub.Close()
	v := uuid.New()
	seedNote(t, reg, v, "board", "- [ ] 😀 card\n- [ ] b\n")
	cl := newClient(t, hub, v, "board")
	defer cl.close(hub)

	res, err := hub.ApplyPlanned(context.Background(), v, "board", moveFirstLineToEnd,
		ApplyOptions{Origin: "op:cli", WantText: true})
	if err != nil {
		t.Fatal(err)
	}
	want := "- [ ] b\n- [ ] 😀 card\n"
	if !res.Changed || res.Text != want {
		t.Fatalf("res %+v", res)
	}
	if err := cl.doc.ApplyUpdate(recvUpdate(t, cl.sub)); err != nil {
		t.Fatal(err)
	}
	if got, _ := cl.doc.Text(); got != want {
		t.Fatalf("client replica %q, want %q", got, want)
	}
	rows, _ := repo.ListUpdatesSince(context.Background(), v, "board", 0, 0)
	if len(rows) != 1 || rows[0].OriginKind != "op:cli" {
		t.Fatalf("log %+v", rows)
	}
}

func TestApplyPlanned_RefusesClientOriginsAndHonoursGuard(t *testing.T) {
	reg := crdt.NewRegistry(newMemRepo())
	mirror := uuid.New()
	errRO := errors.New("read only")
	hub := NewHub(reg, WithWriteGuard(func(v uuid.UUID, origin string) error {
		if v == mirror && !strings.HasPrefix(origin, "federation:") {
			return errRO
		}
		return nil
	}))
	defer hub.Close()
	v := uuid.New()
	seedNote(t, reg, v, "n", "a\nb\n")
	seedNote(t, reg, mirror, "n", "a\nb\n")
	ctx := context.Background()
	for _, origin := range []string{OriginLive, "", "federation:https://home"} {
		if _, err := hub.ApplyPlanned(ctx, v, "n", moveFirstLineToEnd, ApplyOptions{Origin: origin}); !errors.Is(err, ErrPlannedOrigin) {
			t.Fatalf("%q: err %v", origin, err)
		}
	}
	if _, err := hub.ApplyPlanned(ctx, mirror, "n", moveFirstLineToEnd, ApplyOptions{Origin: "ai:mcp"}); !errors.Is(err, errRO) {
		t.Fatalf("mirror: err %v", err)
	}
	// Invalid edits from a planner change nothing.
	_, err := hub.ApplyPlanned(ctx, v, "n", func(string) ([]crdt.Edit, error) {
		return []crdt.Edit{{Pos: 99, Ins: "x"}}, nil
	}, ApplyOptions{Origin: "op:web"})
	if !errors.Is(err, crdt.ErrInvalidEdits) {
		t.Fatalf("invalid edits: %v", err)
	}
	var txt string
	_ = hub.View(ctx, v, "n", func(d *crdt.Doc) error { txt, _ = d.Text(); return nil })
	if txt != "a\nb\n" {
		t.Fatalf("text changed: %q", txt)
	}
}

// Planned edits and live typing interleave safely: each planner sees the
// text as it is under the room lock, so every planned append and every
// live keystroke survives (run with -race).
func TestApplyPlanned_ConcurrentWithLiveEdits(t *testing.T) {
	repo := newMemRepo()
	reg := crdt.NewRegistry(repo)
	hub := NewHub(reg, WithMirrorDebounce(0))
	defer hub.Close()
	v := uuid.New()
	cl := newClient(t, hub, v, "n")
	defer cl.close(hub)

	const n = 50
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			_, err := hub.ApplyPlanned(context.Background(), v, "n", func(text string) ([]crdt.Edit, error) {
				return []crdt.Edit{{Pos: len(utf16.Encode([]rune(text))), Ins: "🎉"}}, nil
			}, ApplyOptions{Origin: "ai:mcp"})
			if err != nil {
				t.Error(err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			cl.absorb()
			if err := cl.room.ApplyAndBroadcast(cl.edit("k"), cl.sub, uuid.Nil); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	wg.Wait()
	txt := replayLog(t, repo, v, "n")
	if strings.Count(txt, "🎉") != n || strings.Count(txt, "k") != n {
		t.Fatalf("lost edits: %d planned, %d live in %q", strings.Count(txt, "🎉"), strings.Count(txt, "k"), txt)
	}
}

// BenchmarkHubApplyPlanned is the planned-op path (acquire, plan under
// the lock, one yrs txn, group commit, broadcast) on a 20 KB note.
func BenchmarkHubApplyPlanned(b *testing.B) {
	repo := newMemRepo()
	reg := crdt.NewRegistry(repo)
	hub := NewHub(reg, WithMirrorDebounce(0))
	defer hub.Close()
	v := uuid.New()
	body := strings.Repeat("- [ ] tarefa 😀 com acentuação\n", 20<<10/36)
	if err := reg.InitFromText(context.Background(), v, "n", body, uuid.Nil, "seed"); err != nil {
		b.Fatal(err)
	}
	cl := newClient(b, hub, v, "n") // keeps the room live
	defer cl.close(hub)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-cl.sub.Out:
			case <-stop:
				return
			}
		}
	}()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := hub.ApplyPlanned(context.Background(), v, "n", moveFirstLineToEnd, ApplyOptions{Origin: "op:bench"}); err != nil {
			b.Fatal(err)
		}
	}
}
