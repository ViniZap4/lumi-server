package crdt

import (
	"math/rand"
	"strings"
	"testing"
	"unicode/utf16"
)

// applyHunksUTF16 replays hunks on old (right to left) in UTF-16 space.
func applyHunksUTF16(old string, hs []textHunk) string {
	u := utf16.Encode([]rune(old))
	for i := len(hs) - 1; i >= 0; i-- {
		h := hs[i]
		ins := utf16.Encode([]rune(h.Insert))
		u = append(u[:h.Index:h.Index], append(ins, u[h.Index+h.DelLen:]...)...)
	}
	return string(utf16.Decode(u))
}

func TestDiffHunks_Property(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	alphabet := []string{"a", "b", "\n", "😀", "é", " ", "c\n"}
	gen := func() string {
		var sb strings.Builder
		for i := rng.Intn(40); i > 0; i-- {
			sb.WriteString(alphabet[rng.Intn(len(alphabet))])
		}
		return sb.String()
	}
	for i := 0; i < 3000; i++ {
		a, b := gen(), gen()
		hs := diffHunks(a, b)
		if got := applyHunksUTF16(a, hs); got != b {
			t.Fatalf("diff %q -> %q replayed to %q (hunks %+v)", a, b, got, hs)
		}
		for k := 1; k < len(hs); k++ {
			if hs[k].Index < hs[k-1].Index+hs[k-1].DelLen {
				t.Fatalf("overlapping hunks %+v", hs)
			}
		}
	}
}

func TestDiffHunks_DistantEditsAreSeparate(t *testing.T) {
	old := "title\nline one\nline two\nline three\nfooter\n"
	neu := "Title\nline one\nline two\nline three\nfooter!\n"
	hs := diffHunks(old, neu)
	if len(hs) != 2 {
		t.Fatalf("hunks = %+v, want 2 small hunks", hs)
	}
	for _, h := range hs {
		if h.DelLen > 1 || len(h.Insert) > 1 {
			t.Fatalf("hunk not minimal: %+v", h)
		}
	}
}

// S10: with a single prefix/suffix hunk, a TUI edit touching the first and
// last line deleted and re-inserted everything between, displacing a
// concurrent insert in the middle. Multi-hunk keeps it in place.
func TestThreeWay_DistantEditsKeepConcurrentMiddleInsert(t *testing.T) {
	server := mustDocFromText(t, "a\nmiddle\nz\n")
	defer server.Close()
	base := mustState(t, server)
	web := fork(t, server)
	upd, _ := web.ApplyTextDiff("a\nmid-WEB-dle\nz\n", "web")
	web.Close()
	if err := server.ApplyUpdate(upd); err != nil {
		t.Fatal(err)
	}
	res, err := ThreeWayUpdate(base, "A\nmiddle\nZ\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := server.ApplyUpdate(res.Update); err != nil {
		t.Fatal(err)
	}
	if got := mustText(t, server); got != "A\nmid-WEB-dle\nZ\n" {
		t.Fatalf("got %q", got)
	}
}

func TestMyers_FallsBackBeyondCap(t *testing.T) {
	var a, b []string
	for i := 0; i < maxDiffD+10; i++ {
		a = append(a, "x\n")
		b = append(b, "y\n")
	}
	if _, ok := myers(a, b); ok {
		t.Fatal("expected cap to trigger")
	}
	old, neu := strings.Join(a, ""), strings.Join(b, "")
	if got := applyHunksUTF16(old, diffHunks(old, neu)); got != neu {
		t.Fatal("fallback diff incorrect")
	}
}

func TestApplyTextDiff_PropertyThroughYrs(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	alphabet := []string{"a", "\n", "😀", "ç", " ", "line\n"}
	d := NewDoc()
	defer d.Close()
	for i := 0; i < 500; i++ {
		var sb strings.Builder
		for n := rng.Intn(30); n > 0; n-- {
			sb.WriteString(alphabet[rng.Intn(len(alphabet))])
		}
		want := sb.String()
		if _, err := d.ApplyTextDiff(want, "p"); err != nil {
			t.Fatal(err)
		}
		if got := mustText(t, d); got != want {
			t.Fatalf("step %d: got %q want %q", i, got, want)
		}
	}
}
