package crdt

import (
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"
)

// Fuzz targets for the diff and the 3-way merge (Phase 3 quality harness,
// docs/phase3/research/09 Q6). Local session:
//
//	GOTOOLCHAIN=go1.25.5 go test ./internal/crdt -run '^$' -fuzz FuzzDiffHunks -fuzztime 2m
//
// The nightly CI job (`.gitea/workflows/fuzz-nightly.yml`) runs each
// target longer. A crasher is written to testdata/fuzz/<Target>/ and then
// replays on every plain `go test`.

// textInput keeps fuzzed strings inside what the server can ever hold as
// note text: valid UTF-8 (JSON decoding and notes.go:483 reject the rest)
// without NUL (a C string boundary for yffi).
func textInput(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}

// applyHunks applies hunks (ascending, offsets into the OLD text in UTF-16
// units) and fails on overlap or out-of-range offsets.
func applyHunks(t *testing.T, old string, hs []textHunk) string {
	t.Helper()
	u := utf16.Encode([]rune(old))
	var out []uint16
	pos := 0
	for _, h := range hs {
		if h.Index < pos || h.DelLen < 0 || h.Index+h.DelLen > len(u) {
			t.Fatalf("hunk %+v out of order or range (pos %d, len %d)", h, pos, len(u))
		}
		// A hunk must never split a surrogate pair.
		if h.Index > 0 && h.Index < len(u) && utf16.IsSurrogate(rune(u[h.Index])) && u[h.Index] >= 0xDC00 {
			t.Fatalf("hunk %+v starts inside a surrogate pair", h)
		}
		if end := h.Index + h.DelLen; end > 0 && end < len(u) && u[end] >= 0xDC00 && u[end] <= 0xDFFF {
			t.Fatalf("hunk %+v ends inside a surrogate pair", h)
		}
		out = append(out, u[pos:h.Index]...)
		out = append(out, utf16.Encode([]rune(h.Insert))...)
		pos = h.Index + h.DelLen
	}
	out = append(out, u[pos:]...)
	return string(utf16.Decode(out))
}

func seedTexts(f *testing.F) {
	f.Add("", "", "")
	f.Add("hello world", "hello brave world", "hello world!")
	f.Add("A\nB\nC\n", "A\nmiddle\nB\nC\n", "a\nB\nc\n")
	f.Add("😀 emoji\n", "😀😀 emoji\n", "x😀 emoji\n")
	f.Add("linha\r\noutra\r\n", "linha\r\n", "")
	f.Add("ação", "acão", "ação ")
}

// FuzzDiffHunks: applying the hunks to the old text yields the new text,
// hunks are ordered and disjoint, and never split a code point.
func FuzzDiffHunks(f *testing.F) {
	seedTexts(f)
	f.Fuzz(func(t *testing.T, old, _ string, neu string) {
		if !utf8.ValidString(old) || !utf8.ValidString(neu) {
			return
		}
		hs := diffHunks(old, neu)
		if old == neu && len(hs) != 0 {
			t.Fatalf("no-op diff produced hunks %+v", hs)
		}
		for _, h := range hs {
			if h.DelLen == 0 && h.Insert == "" {
				t.Fatalf("empty hunk %+v", h)
			}
		}
		if got := applyHunks(t, old, hs); got != neu {
			t.Fatalf("diff(%q,%q) applied gives %q", old, neu, got)
		}
	})
}

func docWith(t *testing.T, text string) *Doc {
	t.Helper()
	d := NewDoc()
	if _, err := d.ApplyTextDiff(text, ""); err != nil {
		t.Fatal(err)
	}
	return d
}

func textOf(t *testing.T, d *Doc) string {
	t.Helper()
	s, err := d.Text()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// FuzzThreeWayUpdate drives the opaque-editor merge (protocol §7):
//   - the 3-way update applied to the base reproduces the edited text;
//   - applied to a live doc that moved on concurrently, it converges, and
//     when the two edits touch disjoint line blocks both survive (V9b).
func FuzzThreeWayUpdate(f *testing.F) {
	seedTexts(f)
	f.Fuzz(func(t *testing.T, base, concurrent, edited string) {
		if !textInput(base) || !textInput(concurrent) || !textInput(edited) {
			return
		}
		if len(base)+len(concurrent)+len(edited) > 1<<14 {
			return
		}
		baseDoc := docWith(t, base)
		defer baseDoc.Close()
		state, err := baseDoc.EncodeStateAsUpdate()
		if err != nil {
			t.Fatal(err)
		}
		res, err := ThreeWayUpdate(state, edited)
		if err != nil {
			t.Fatalf("ThreeWayUpdate: %v", err)
		}
		if res.BaseText != base {
			t.Fatalf("base text %q, want %q", res.BaseText, base)
		}

		// 1. On the base itself the update reproduces the edit exactly.
		onBase, err := LoadDoc(state)
		if err != nil {
			t.Fatal(err)
		}
		defer onBase.Close()
		if err := onBase.ApplyUpdate(res.Update); err != nil {
			t.Fatal(err)
		}
		if got := textOf(t, onBase); got != edited {
			t.Fatalf("3-way on base: got %q want %q", got, edited)
		}

		// 2. On a live doc with a concurrent edit, both replicas converge.
		live, err := LoadDoc(state)
		if err != nil {
			t.Fatal(err)
		}
		defer live.Close()
		cu, err := live.ApplyTextDiff(concurrent, "peer")
		if err != nil {
			t.Fatal(err)
		}
		if err := live.ApplyUpdate(res.Update); err != nil {
			t.Fatal(err)
		}
		if len(cu) > 0 {
			if err := onBase.ApplyUpdate(cu); err != nil {
				t.Fatal(err)
			}
		}
		a, b := textOf(t, live), textOf(t, onBase)
		if a != b {
			t.Fatalf("replicas diverged: %q vs %q", a, b)
		}
		if pending, _ := live.HasPending(); pending {
			t.Fatal("3-way update left pending structs")
		}
	})
}

// FuzzApplyUpdate feeds arbitrary bytes to the update decoder, which is
// what any editor socket can send (wsync) and what LoadDoc reads from
// Postgres. It must return an error, never crash the process.
func FuzzApplyUpdate(f *testing.F) {
	d := NewDoc()
	_, _ = d.ApplyTextDiff("hello world\n", "")
	full, _ := d.EncodeStateAsUpdate()
	d2, _ := LoadDoc(full)
	sv, _ := d2.StateVectorV1()
	_, _ = d2.ApplyTextDiff("hello brave world\n", "")
	delta, _ := d2.EncodeDiffSince(sv)
	d.Close()
	d2.Close()
	f.Add([]byte{0, 0})
	f.Add(full)
	f.Add(delta)
	f.Add([]byte{1, 1, 0xff, 0xff, 0xff, 0xff, 0x0f, 0, 4})
	f.Fuzz(func(t *testing.T, update []byte) {
		doc, err := LoadDoc(full)
		if err != nil {
			t.Fatal(err)
		}
		defer doc.Close()
		_, _ = doc.ApplyUpdateChanged(update)
		_, _ = doc.Text()
		_, _ = doc.StateVectorV1()
		_, _ = doc.HasPending()
		_, _ = DecodeStateVector(update)
	})
}
