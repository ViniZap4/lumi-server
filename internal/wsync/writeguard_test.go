package wsync

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/crdt"
)

// A mirror vault takes CRDT writes from its home link only: the hub's
// write guard refuses every other origin before the doc changes.
func TestWriteGuardRefusesBeforeApplying(t *testing.T) {
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
	seedNote(t, reg, mirror, "n", "home text")
	ctx := context.Background()

	for _, origin := range []string{OriginLive, "web-patch", OriginFSWatcher, "tui-diff"} {
		if _, err := hub.ApplyText(ctx, mirror, "n", "local edit", nil, ApplyOptions{Origin: origin}); !errors.Is(err, errRO) {
			t.Fatalf("%s: %v", origin, err)
		}
	}
	d, _ := reg.LoadDoc(ctx, mirror, "n")
	update, _ := d.ApplyTextDiff("via update", "x")
	d.Close()
	if _, err := hub.ApplyUpdate(ctx, mirror, "n", update, ApplyOptions{Origin: OriginLive}); !errors.Is(err, errRO) {
		t.Fatalf("update: %v", err)
	}
	var txt string
	_ = hub.View(ctx, mirror, "n", func(doc *crdt.Doc) error { txt, _ = doc.Text(); return nil })
	if txt != "home text" {
		t.Fatalf("mirror doc changed: %q", txt)
	}
	if _, err := hub.ApplyText(ctx, mirror, "n", "from home", nil, ApplyOptions{Origin: "federation:https://home.example"}); err != nil {
		t.Fatalf("home write refused: %v", err)
	}
	// Other vaults are untouched by the guard.
	other := uuid.New()
	seedNote(t, reg, other, "n", "a")
	if _, err := hub.ApplyText(ctx, other, "n", "b", nil, ApplyOptions{Origin: OriginLive}); err != nil {
		t.Fatal(err)
	}
}
