package crdt

// Benchmarks for the CRDT hot paths (docs/PERF-BUDGETS.md, umbrella).
// CI runs them on the PR and on main and blocks a > 10 % regression
// that benchstat calls significant (scripts/bench-gate.sh).
//
//   GOTOOLCHAIN=go1.25.5 go test -run '^$' -bench . -benchmem ./internal/crdt

import (
	"fmt"
	"strings"
	"testing"

	"github.com/ViniZap4/lumi-server/internal/perfcorpus"
)

var benchSizes = []int{20 * perfcorpus.KB, 200 * perfcorpus.KB}

func sizeName(n int) string { return fmt.Sprintf("%dKB", n/perfcorpus.KB) }

func benchDoc(b *testing.B, text string) *Doc {
	b.Helper()
	d := NewDoc()
	if _, err := d.ApplyTextDiff(text, "bench"); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = d.Close() })
	return d
}

// keystrokeUpdates returns n single-character updates typed in the
// middle of text on a replica of state, in order: what a live client
// sends while typing.
func keystrokeUpdates(b *testing.B, state []byte, text string, n int) [][]byte {
	b.Helper()
	replica, err := LoadDoc(state)
	if err != nil {
		b.Fatal(err)
	}
	defer replica.Close()
	at := perfcorpus.MidPoint(text)
	out := make([][]byte, n)
	cur := text
	for i := range out {
		cur = cur[:at+i] + "x" + cur[at+i:]
		u, err := replica.ApplyTextDiff(cur, "client")
		if err != nil {
			b.Fatal(err)
		}
		out[i] = u
	}
	return out
}

// keystrokePool is how many keystroke updates are generated per size.
// Each run of keystrokePool iterations replays them on a doc freshly
// loaded from the same state, so generating updates (O(note) each)
// stays off the clock and out of b.N's growth.
const keystrokePool = 256

// BenchmarkDocApplyUpdate: yrs merge of one live keystroke update into
// the authoritative doc (the first step of wsync commitLocked).
func BenchmarkDocApplyUpdate(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(sizeName(size), func(b *testing.B) {
			text := perfcorpus.Prose(size)
			state, err := benchDoc(b, text).EncodeStateAsUpdate()
			if err != nil {
				b.Fatal(err)
			}
			updates := keystrokeUpdates(b, state, text, keystrokePool)
			var d *Doc
			defer func() {
				if d != nil {
					_ = d.Close()
				}
			}()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if i%keystrokePool == 0 {
					b.StopTimer()
					if d != nil {
						_ = d.Close()
					}
					if d, err = LoadDoc(state); err != nil {
						b.Fatal(err)
					}
					b.StartTimer()
				}
				if _, err := d.ApplyUpdateChanged(updates[i%keystrokePool]); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkDocTextAndStateVector: Text() + StateVectorV1(), which wsync
// resultLocked runs only when a caller asks for it (ApplyOptions.WantText:
// the REST/3-way paths); the live WS commit path no longer pays it.
func BenchmarkDocTextAndStateVector(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(sizeName(size), func(b *testing.B) {
			d := benchDoc(b, perfcorpus.Prose(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := d.Text(); err != nil {
					b.Fatal(err)
				}
				if _, err := d.StateVectorV1(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkApplyTextDiff: PATCH/fswatch/3-way lowering of a new full
// text into minimal ranged ops, for one inserted character and for one
// rewritten paragraph.
func BenchmarkApplyTextDiff(b *testing.B) {
	for _, size := range benchSizes {
		text := perfcorpus.Prose(size)
		at := perfcorpus.MidPoint(text)
		end := at + strings.Index(text[at:], "\n\n")
		cases := map[string][2]string{
			"char":      {text, text[:at] + "x" + text[at:]},
			"paragraph": {text, text[:at] + strings.ToUpper(text[at:end]) + text[end:]},
		}
		for _, name := range []string{"char", "paragraph"} {
			c := cases[name]
			b.Run(sizeName(size)+"/"+name, func(b *testing.B) {
				d := benchDoc(b, c[0])
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					// Alternate so every iteration is a real one-hunk change.
					target := c[1]
					if i%2 == 1 {
						target = c[0]
					}
					if _, err := d.ApplyTextDiff(target, "bench"); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// BenchmarkApplyEdits: the server-planned ranged-edit path
// (Doc.ApplyEdits, used by Hub.ApplyPlanned) for the same changes as
// BenchmarkApplyTextDiff, so the two compare case by case: the planner
// reads the text once and skips the line diff.
func BenchmarkApplyEdits(b *testing.B) {
	for _, size := range benchSizes {
		text := perfcorpus.Prose(size)
		at := perfcorpus.MidPoint(text)
		end := at + strings.Index(text[at:], "\n\n")
		pos := utf16Len(text[:at])
		para := text[at:end]
		upper := strings.ToUpper(para)
		paraLen, upperLen := utf16Len(para), utf16Len(upper)
		cases := map[string][2][]Edit{
			"char": {
				{{Pos: pos, Ins: "x"}},
				{{Pos: pos, Del: 1}},
			},
			"paragraph": {
				{{Pos: pos, Del: paraLen, Ins: upper}},
				{{Pos: pos, Del: upperLen, Ins: para}},
			},
		}
		for _, name := range []string{"char", "paragraph"} {
			c := cases[name]
			b.Run(sizeName(size)+"/"+name, func(b *testing.B) {
				d := benchDoc(b, text)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					// Alternate forward and back so every iteration is a
					// real change against the same text.
					if _, err := d.ApplyEdits(c[i%2], "op:bench"); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// BenchmarkThreeWayUpdate: the TUI's /diff path (protocol §7): rebuild
// the base doc from its state, diff base text -> edited text, encode.
func BenchmarkThreeWayUpdate(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(sizeName(size), func(b *testing.B) {
			text := perfcorpus.Prose(size)
			d := benchDoc(b, text)
			base, err := d.EncodeStateAsUpdate()
			if err != nil {
				b.Fatal(err)
			}
			edited := perfcorpus.Edit(text, "an edit from $EDITOR\n\n")
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := ThreeWayUpdate(base, edited); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkDiffHunks: the line-level Myers diff behind ApplyTextDiff,
// with edits scattered through the note (fswatch after an external
// editor reflowed a few paragraphs).
func BenchmarkDiffHunks(b *testing.B) {
	for _, size := range benchSizes {
		b.Run(sizeName(size), func(b *testing.B) {
			text := perfcorpus.Prose(size)
			lines := strings.Split(text, "\n")
			for i := 7; i < len(lines); i += len(lines) / 8 {
				lines[i] = strings.ToUpper(lines[i])
			}
			edited := strings.Join(lines, "\n")
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = diffHunks(text, edited)
			}
		})
	}
}
