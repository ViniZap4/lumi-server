package crdt

import "strings"

// textHunk is one replacement: delete DelLen UTF-16 units at Index (an
// offset into the OLD text) and insert Insert there.
type textHunk struct {
	Index  int
	DelLen int
	Insert string
}

// maxDiffD caps the Myers edit distance (in lines). Beyond it the diff
// degrades to a single prefix/suffix hunk, which is still correct.
const maxDiffD = 1000

// diffHunks computes the edit from old to neu as a list of hunks in
// ascending Index order. It runs a Myers diff over lines, then trims each
// changed block to its minimal rune range, so two distant edits become two
// small hunks instead of one span that deletes and re-inserts everything
// between them (which would displace concurrent edits in that span).
// Offsets are UTF-16 code units; hunks never split a code point.
func diffHunks(old, neu string) []textHunk {
	if old == neu {
		return nil
	}
	// Strip the common prefix/suffix lines first: cheap and shrinks D.
	a, b := splitLines(old), splitLines(neu)
	pre := 0
	for pre < len(a) && pre < len(b) && a[pre] == b[pre] {
		pre++
	}
	suf := 0
	for suf < len(a)-pre && suf < len(b)-pre && a[len(a)-1-suf] == b[len(b)-1-suf] {
		suf++
	}
	am, bm := a[pre:len(a)-suf], b[pre:len(b)-suf]

	ops, ok := myers(am, bm)
	if !ok {
		ops = nil
		for range am {
			ops = append(ops, opDel)
		}
		for range bm {
			ops = append(ops, opIns)
		}
	}

	// Walk the edit script, collecting blocks of non-equal lines.
	var hunks []textHunk
	off := utf16Len(strings.Join(a[:pre], ""))
	i, j := 0, 0
	for k := 0; k < len(ops); {
		if ops[k] == opEq {
			off += utf16Len(am[i])
			i++
			j++
			k++
			continue
		}
		var oldSeg, newSeg strings.Builder
		for k < len(ops) && ops[k] != opEq {
			if ops[k] == opDel {
				oldSeg.WriteString(am[i])
				i++
			} else {
				newSeg.WriteString(bm[j])
				j++
			}
			k++
		}
		os := oldSeg.String()
		hunks = append(hunks, trimHunk(off, os, newSeg.String()))
		off += utf16Len(os)
	}
	return hunks
}

// trimHunk narrows a replaced block to the runes that actually differ.
func trimHunk(off int, oldSeg, newSeg string) textHunk {
	prefix, _, oldMid, newMid := diffSlice(oldSeg, newSeg)
	return textHunk{Index: off + utf16Len(prefix), DelLen: utf16Len(oldMid), Insert: newMid}
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.SplitAfter(s, "\n")
}

const (
	opEq byte = iota
	opDel
	opIns
)

// myers returns the shortest edit script from a to b, or ok=false when
// the edit distance exceeds maxDiffD.
func myers(a, b []string) ([]byte, bool) {
	n, m := len(a), len(b)
	if n == 0 && m == 0 {
		return nil, true
	}
	maxD := n + m
	if maxD > maxDiffD {
		maxD = maxDiffD
	}
	offset := maxD + 1
	v := make([]int, 2*maxD+3)
	var trace [][]int
	for d := 0; d <= maxD; d++ {
		snap := make([]int, len(v))
		copy(snap, v)
		trace = append(trace, snap)
		for k := -d; k <= d; k += 2 {
			var x int
			if k == -d || (k != d && v[offset+k-1] < v[offset+k+1]) {
				x = v[offset+k+1] // down: insertion
			} else {
				x = v[offset+k-1] + 1 // right: deletion
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
			}
			v[offset+k] = x
			if x >= n && y >= m {
				return backtrack(trace, offset, n, m, d), true
			}
		}
	}
	return nil, false
}

func backtrack(trace [][]int, offset, n, m, dEnd int) []byte {
	var ops []byte
	x, y := n, m
	for d := dEnd; d > 0; d-- {
		v := trace[d]
		k := x - y
		var prevK int
		if k == -d || (k != d && v[offset+k-1] < v[offset+k+1]) {
			prevK = k + 1
		} else {
			prevK = k - 1
		}
		prevX := v[offset+prevK]
		prevY := prevX - prevK
		for x > prevX && y > prevY {
			ops = append(ops, opEq)
			x--
			y--
		}
		if x == prevX {
			ops = append(ops, opIns)
		} else {
			ops = append(ops, opDel)
		}
		x, y = prevX, prevY
	}
	for x > 0 && y > 0 {
		ops = append(ops, opEq)
		x--
		y--
	}
	for i, j := 0, len(ops)-1; i < j; i, j = i+1, j-1 {
		ops[i], ops[j] = ops[j], ops[i]
	}
	return ops
}
