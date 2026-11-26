package crdt

import (
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unicode/utf16"
	"unicode/utf8"
)

// refApply is the reference model: apply edits (UTF-16 offsets into the
// original) to text by slicing its UTF-16 encoding.
func refApply(text string, edits []Edit) string {
	src := utf16.Encode([]rune(text))
	var out []uint16
	prev := 0
	for _, e := range edits {
		out = append(out, src[prev:e.Pos]...)
		out = append(out, utf16.Encode([]rune(e.Ins))...)
		prev = e.Pos + e.Del
	}
	out = append(out, src[prev:]...)
	return string(utf16.Decode(out))
}

func seededDoc(t testing.TB, text string) *Doc {
	t.Helper()
	d := NewDoc()
	if text != "" {
		if _, err := d.ApplyTextDiff(text, "seed"); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

// replayOnReplica checks the returned update reproduces the change on an
// independent replica of the pre-edit state.
func replayOnReplica(t testing.TB, before []byte, update []byte, want string) {
	t.Helper()
	r, err := LoadDoc(before)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := r.ApplyUpdate(update); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.Text(); got != want {
		t.Fatalf("replica text %q, want %q", got, want)
	}
}

func TestApplyEdits_Valid(t *testing.T) {
	cases := []struct {
		name  string
		text  string
		edits []Edit
		want  string
	}{
		{"insert at start", "abc", []Edit{{Pos: 0, Ins: "X"}}, "Xabc"},
		{"insert at end", "abc", []Edit{{Pos: 3, Ins: "X"}}, "abcX"},
		{"replace middle", "abc", []Edit{{Pos: 1, Del: 1, Ins: "B"}}, "aBc"},
		{"two disjoint", "hello world", []Edit{{Pos: 0, Del: 1, Ins: "H"}, {Pos: 6, Del: 1, Ins: "W"}}, "Hello World"},
		{"adjacent", "abcd", []Edit{{Pos: 0, Del: 2, Ins: "x"}, {Pos: 2, Del: 2, Ins: "y"}}, "xy"},
		{"same-pos inserts keep order", "ab", []Edit{{Pos: 1, Ins: "1"}, {Pos: 1, Ins: "2"}}, "a12b"},
		{"delete all", "abc", []Edit{{Pos: 0, Del: 3}}, ""},
		{"empty doc insert", "", []Edit{{Pos: 0, Ins: "hi"}}, "hi"},
		// Non-BMP: 😀 is two UTF-16 units.
		{"emoji card move", "- [ ] 😀 a\n- [ ] b\n", []Edit{{Pos: 0, Del: 11}, {Pos: 19, Ins: "- [ ] 😀 a\n"}}, "- [ ] b\n- [ ] 😀 a\n"},
		{"replace surrogate pair whole", "a😀b", []Edit{{Pos: 1, Del: 2, Ins: "😁"}}, "a😁b"},
		{"insert after pair", "😀", []Edit{{Pos: 2, Ins: "x"}}, "😀x"},
		{"ZWJ family kept by bounds", "👨‍👩‍👧!", []Edit{{Pos: 8, Del: 1, Ins: "?"}}, "👨‍👩‍👧?"},
		{"combining mark", "éx", []Edit{{Pos: 2, Del: 1, Ins: "y"}}, "éy"},
		{"empty edits dropped", "abc", []Edit{{Pos: 1}, {Pos: 2, Ins: "Z"}}, "abZc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := seededDoc(t, tc.text)
			defer d.Close()
			before, _ := d.EncodeStateAsUpdate()
			if want := refApply(tc.text, tc.edits); want != tc.want {
				t.Fatalf("reference model gives %q, case wants %q", want, tc.want)
			}
			u, err := d.ApplyEdits(tc.edits, "op:test")
			if err != nil {
				t.Fatal(err)
			}
			got, _ := d.Text()
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
			replayOnReplica(t, before, u, tc.want)
		})
	}
}

func TestApplyEdits_Invalid(t *testing.T) {
	cases := []struct {
		name  string
		text  string
		edits []Edit
	}{
		{"negative pos", "abc", []Edit{{Pos: -1, Ins: "x"}}},
		{"negative del", "abc", []Edit{{Pos: 0, Del: -1}}},
		{"past end", "abc", []Edit{{Pos: 4, Ins: "x"}}},
		{"delete past end", "abc", []Edit{{Pos: 2, Del: 2}}},
		{"overlap", "abcdef", []Edit{{Pos: 0, Del: 3}, {Pos: 2, Del: 1}}},
		{"out of order", "abcdef", []Edit{{Pos: 3, Ins: "x"}, {Pos: 1, Ins: "y"}}},
		{"pos splits pair", "a😀b", []Edit{{Pos: 2, Ins: "x"}}},
		{"end splits pair", "a😀b", []Edit{{Pos: 0, Del: 2}}},
		{"pair split at end of text", "😀", []Edit{{Pos: 1, Del: 1}}},
		{"NUL insert", "abc", []Edit{{Pos: 1, Ins: "x\x00y"}}},
		{"invalid utf8", "abc", []Edit{{Pos: 1, Ins: "\xff"}}},
		{"past end on empty", "", []Edit{{Pos: 1, Ins: "x"}}},
		{"empty edit past end", "0", []Edit{{Pos: 1, Ins: "ab"}, {Pos: 2}}},
		{"empty edit splits pair", "😀", []Edit{{Pos: 1}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := seededDoc(t, tc.text)
			defer d.Close()
			svBefore, _ := d.StateVectorV1()
			u, err := d.ApplyEdits(tc.edits, "op:test")
			if !errors.Is(err, ErrInvalidEdits) {
				t.Fatalf("err = %v (update %d bytes), want ErrInvalidEdits", err, len(u))
			}
			got, _ := d.Text()
			svAfter, _ := d.StateVectorV1()
			if got != tc.text || string(svBefore) != string(svAfter) {
				t.Fatalf("doc changed on invalid edits: %q", got)
			}
		})
	}
}

func TestApplyEdits_NoOp(t *testing.T) {
	d := seededDoc(t, "abc")
	defer d.Close()
	u, err := d.ApplyEdits([]Edit{{Pos: 1}}, "op:test")
	if err != nil || len(u) != 0 {
		t.Fatalf("u=%v err=%v, want empty update", u, err)
	}
	u, err = d.ApplyEdits(nil, "op:test")
	if err != nil || len(u) != 0 {
		t.Fatalf("u=%v err=%v, want empty update", u, err)
	}
}

func TestApplyPlanned_PlannerSeesCurrentTextAndErrors(t *testing.T) {
	d := seededDoc(t, "one two")
	defer d.Close()
	_, err := d.ApplyPlanned(func(text string) ([]Edit, error) {
		i := strings.Index(text, "two")
		return []Edit{{Pos: i, Del: 3, Ins: "três"}}, nil
	}, "op:test")
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := d.Text(); got != "one três" {
		t.Fatalf("got %q", got)
	}
	boom := errors.New("stale ref")
	if _, err := d.ApplyPlanned(func(string) ([]Edit, error) { return nil, boom }, "op:test"); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if got, _ := d.Text(); got != "one três" {
		t.Fatalf("planner error changed the doc: %q", got)
	}
}

// Concurrent planned edits never interleave read and write: each planner
// appends one character at the end it observed, so N planners yield
// exactly N characters.
func TestApplyPlanned_Atomic(t *testing.T) {
	d := seededDoc(t, "")
	defer d.Close()
	var wg sync.WaitGroup
	const n = 64
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := d.ApplyPlanned(func(text string) ([]Edit, error) {
				return []Edit{{Pos: utf16Len(text), Ins: "😀"}}, nil
			}, "op:test")
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	got, _ := d.Text()
	if got != strings.Repeat("😀", n) {
		t.Fatalf("got %d runes, want %d", utf8.RuneCountInString(got), n)
	}
}

func TestByteEditsToUTF16(t *testing.T) {
	text := "a😀é b"
	// bytes: a(0) 😀(1..4) é(5..6) ' '(7) b(8)
	got, err := ByteEditsToUTF16(text, []Edit{{Pos: 1, Del: 4, Ins: "X"}, {Pos: 8, Del: 1, Ins: "B"}})
	if err != nil {
		t.Fatal(err)
	}
	want := []Edit{{Pos: 1, Del: 2, Ins: "X"}, {Pos: 5, Del: 1, Ins: "B"}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %+v want %+v", got, want)
	}
	if refApply(text, got) != "aXé B" {
		t.Fatalf("converted edits apply to %q", refApply(text, got))
	}
	for _, bad := range [][]Edit{
		{{Pos: 2, Ins: "x"}},           // inside 😀
		{{Pos: 0, Del: 6}},             // ends inside é
		{{Pos: 9, Ins: "x"}, {Pos: 1}}, // out of order
		{{Pos: 10, Ins: "x"}},          // past the end
		{{Pos: -1}},                    // negative
	} {
		if _, err := ByteEditsToUTF16(text, bad); !errors.Is(err, ErrInvalidEdits) {
			t.Errorf("%+v: err = %v, want ErrInvalidEdits", bad, err)
		}
	}
}

// FuzzApplyEdits drives random edit batches (including ones whose
// boundaries split surrogate pairs) against the UTF-16 reference model.
// Valid batches must match the model, and their update must reproduce
// the result on a replica; invalid ones must be refused untouched.
func FuzzApplyEdits(f *testing.F) {
	seeds := []struct {
		text string
		ops  []byte
	}{
		{"hello world", []byte{0, 1, 'x', 5, 2, 'y'}},
		{"a😀b😁c", []byte{1, 0, 'z', 1, 2, 0}},
		{"- [ ] 😀 card\n- [x] done 🎉\n", []byte{0, 11, 0, 3, 0, 'q'}},
		{"👨‍👩‍👧 família ação", []byte{2, 3, 'e', 7, 1, 0}},
		{"𝔘𝔫𝔦𝔠𝔬𝔡𝔢", []byte{1, 1, 'w', 1, 1, 'v'}},
		{"", []byte{0, 0, 'a'}},
	}
	for _, s := range seeds {
		f.Add(s.text, s.ops)
	}
	inserts := []string{"", "x", "😀", "é", "\n", "🎉z", "ab"}
	f.Fuzz(func(t *testing.T, text string, ops []byte) {
		text = strings.ToValidUTF8(strings.ReplaceAll(text, "\x00", ""), "?")
		if len(text) > 4096 || len(ops) > 96 {
			return
		}
		n := len(utf16.Encode([]rune(text)))
		// Each op is 3 bytes: gap since previous end, delete length,
		// insert index. Gaps/deletes are raw UTF-16 units, so boundaries
		// can land inside a surrogate pair or past the end.
		var edits []Edit
		pos := 0
		for i := 0; i+2 < len(ops); i += 3 {
			pos += int(ops[i] % 16)
			del := int(ops[i+1] % 8)
			edits = append(edits, Edit{Pos: pos, Del: del, Ins: inserts[int(ops[i+2])%len(inserts)]})
			pos += del
		}
		valid := pos <= n && boundariesOK(text, edits)

		d := seededDoc(t, text)
		defer d.Close()
		before, _ := d.EncodeStateAsUpdate()
		u, err := d.ApplyEdits(edits, "op:fuzz")
		got, _ := d.Text()
		if !valid {
			if !errors.Is(err, ErrInvalidEdits) {
				t.Fatalf("invalid batch %+v on %q accepted (err=%v)", edits, text, err)
			}
			if got != text {
				t.Fatalf("invalid batch changed the doc: %q", got)
			}
			return
		}
		if err != nil {
			t.Fatalf("valid batch %+v on %q refused: %v", edits, text, err)
		}
		want := refApply(text, edits)
		if got != want {
			t.Fatalf("text %q edits %+v: got %q want %q", text, edits, got, want)
		}
		if len(u) > 0 {
			replayOnReplica(t, before, u, want)
		} else if want != text {
			t.Fatalf("empty update for a change")
		}
	})
}

// boundariesOK reports whether every edit boundary is on a code point.
func boundariesOK(text string, edits []Edit) bool {
	starts := map[int]bool{}
	unit := 0
	for _, r := range text {
		starts[unit] = true
		if r > 0xFFFF {
			unit += 2
		} else {
			unit++
		}
	}
	starts[unit] = true
	for _, e := range edits {
		if !starts[e.Pos] || !starts[e.Pos+e.Del] {
			return false
		}
	}
	return true
}

func benchText(size int) string {
	line := "- [ ] tarefa com acentuação e emoji 😀 #tag\n"
	return strings.Repeat(line, size/len(line)+1)[:size-size%len(line)]
}

// BenchmarkApplyEdits measures a planned edit (insert, then delete, one
// character at the start, as BenchmarkApplyTextDiff does) on notes of
// 20 KB and 200 KB. The planner path reads the text once and skips the
// diff; compare with BenchmarkApplyTextDiff.
func BenchmarkApplyEdits(b *testing.B) {
	for _, size := range []int{20 << 10, 200 << 10} {
		b.Run(sizeName(size), func(b *testing.B) {
			d := seededDoc(b, benchText(size))
			defer d.Close()
			batches := [2][]Edit{{{Pos: 0, Ins: "x"}}, {{Pos: 0, Del: 1}}}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := d.ApplyEdits(batches[i%2], "op:bench"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkApplyTextDiff is the whole-text alternative for comparison.
func BenchmarkApplyTextDiff(b *testing.B) {
	for _, size := range []int{20 << 10, 200 << 10} {
		b.Run(sizeName(size), func(b *testing.B) {
			base := benchText(size)
			d := seededDoc(b, base)
			defer d.Close()
			texts := [2]string{"x" + base, base}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := d.ApplyTextDiff(texts[i%2], "bench"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func sizeName(n int) string { return strconv.Itoa(n>>10) + "KB" }
