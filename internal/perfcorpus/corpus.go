// Package perfcorpus generates the deterministic benchmark corpora of
// docs/PERF-BUDGETS.md (umbrella repo, "Corpora"). It follows the same
// recipe as web-client/src/bench/corpus.ts: a mulberry32 PRNG with a
// fixed seed, a fixed word list and a real-note block mix, so every
// client benchmarks comparable text without committing megabytes of
// fixtures. Only benchmarks and tests import it.
package perfcorpus

import (
	"fmt"
	"strings"
)

// KB is the corpus size unit (1024 bytes).
const KB = 1024

// Rand is mulberry32: tiny, fast and identical across languages.
type Rand struct{ a uint32 }

// NewRand seeds a mulberry32 generator.
func NewRand(seed uint32) *Rand { return &Rand{a: seed} }

// Float returns the next value in [0, 1).
func (r *Rand) Float() float64 {
	r.a += 0x6d2b79f5
	t := r.a
	t = (t ^ (t >> 15)) * (t | 1)
	t ^= t + (t^(t>>7))*(t|61)
	return float64(t^(t>>14)) / 4294967296
}

// Intn returns the next value in [0, n).
func (r *Rand) Intn(n int) int { return int(r.Float() * float64(n)) }

var words = strings.Fields(
	"nota livro papel respira lumi sync editor vim canvas kanban sprint tarefa ideia projeto rascunho " +
		"the quick brown fox jumps over lazy dog paper breathes local first markdown frontmatter yjs crdt " +
		"servidor cliente espelho selado tempo leitura escrita fluxo foco calma luz sombra margem linha " +
		"render preview split pane explorer palette legend motion spring frame budget gate bench corpus")

// Words returns n space-separated words.
func Words(r *Rand, n int) string {
	out := make([]string, n)
	for i := range out {
		out[i] = words[r.Intn(len(words))]
	}
	return strings.Join(out, " ")
}

func sentence(r *Rand) string {
	s := Words(r, 6+r.Intn(12))
	return strings.ToUpper(s[:1]) + s[1:] + "."
}

func inline(r *Rand) string {
	s := sentence(r)
	k := r.Float()
	wrap := func(open, close string) string {
		i := strings.IndexByte(s, ' ')
		j := strings.IndexByte(s[i+1:], ' ')
		if i < 0 || j < 0 {
			return s
		}
		j += i + 1
		return s[:i+1] + open + s[i+1:j] + close + s[j:]
	}
	switch {
	case k < 0.15:
		return wrap("**", "**")
	case k < 0.25:
		return wrap("*", "*")
	case k < 0.35:
		return wrap("`", "`")
	case k < 0.45:
		return wrap("[[", "]]")
	case k < 0.5:
		i := strings.IndexByte(s, ' ')
		j := strings.IndexByte(s[i+1:], ' ') + i + 1
		w := s[i+1 : j]
		return s[:i+1] + "[" + w + "](https://example.com/" + w + ")" + s[j:]
	case k < 0.55:
		return wrap("==", "==")
	}
	return s
}

func proseBlock(r *Rand, i int) string {
	k := r.Float()
	if i%9 == 0 {
		return strings.Repeat("#", 1+r.Intn(3)) + " " + Words(r, 3+r.Intn(4))
	}
	lines := func(n int, f func() string) string {
		out := make([]string, n)
		for j := range out {
			out[j] = f()
		}
		return strings.Join(out, "\n")
	}
	switch {
	case k < 0.45:
		n := 2 + r.Intn(4)
		out := make([]string, n)
		for j := range out {
			out[j] = inline(r)
		}
		return strings.Join(out, " ")
	case k < 0.58:
		return lines(3+r.Intn(4), func() string { return "- " + inline(r) })
	case k < 0.68:
		return lines(2+r.Intn(4), func() string {
			mark := " "
			if r.Float() < 0.4 {
				mark = "x"
			}
			return "- [" + mark + "] " + Words(r, 4+r.Intn(6))
		})
	case k < 0.74:
		return "> " + inline(r) + "\n> " + inline(r)
	case k < 0.8:
		return "> [!note] " + Words(r, 3) + "\n> " + inline(r) + "\n> " + inline(r)
	case k < 0.87:
		return "```go\n" + lines(3+r.Intn(6), func() string { return "\t" + Words(r, 3) + "()" }) + "\n```"
	case k < 0.93:
		row := func() string { return fmt.Sprintf("| %s | %s | %d |", Words(r, 1), Words(r, 2), r.Intn(1000)) }
		return strings.Join([]string{"| a | b | c |", "|---|---|---|", row(), row(), row()}, "\n")
	}
	return fmt.Sprintf("%s[^%d]\n\n[^%d]: %s", inline(r), i, i, sentence(r))
}

// Prose returns a deterministic real-shaped markdown note of at least
// `bytes` bytes (one top-level block per ~400 B).
func Prose(bytes int) string {
	r := NewRand(0x101)
	var b strings.Builder
	b.Grow(bytes + 1024)
	// size counts every block plus a separator, like corpus.ts, so both
	// stop at the same block.
	for i, size := 0, 0; size < bytes; i++ {
		if i > 0 {
			b.WriteString("\n\n")
		}
		blk := proseBlock(r, i)
		b.WriteString(blk)
		size += len(blk) + 2
	}
	b.WriteByte('\n')
	return b.String()
}

// Edit returns text with s inserted at the first paragraph boundary
// past the middle: the "one keystroke in the middle of the note" case.
func Edit(text, s string) string {
	at := MidPoint(text)
	return text[:at] + s + text[at:]
}

// MidPoint is the byte offset of the first block start past the middle.
func MidPoint(text string) int {
	i := strings.Index(text[len(text)/2:], "\n\n")
	if i < 0 {
		return len(text) / 2
	}
	return len(text)/2 + i + 2
}
