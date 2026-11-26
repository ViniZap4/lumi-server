package perfcorpus

import (
	"fmt"
	"hash/fnv"
	"testing"
)

// The corpus must stay byte-identical to web-client/src/bench/corpus.ts
// (its corpus.test.ts records the same hash), so server, TUI and web
// benchmarks measure the same text. Changing the recipe changes every
// baseline: update both generators and both hashes together.
func TestProseMatchesWebCorpus(t *testing.T) {
	h := fnv.New32a()
	_, _ = h.Write([]byte(Prose(20 * KB)))
	if got := fmt.Sprintf("%08x", h.Sum32()); got != "47f87eb1" {
		t.Fatalf("Prose(20 KB) fnv1a = %s, want 47f87eb1 (web corpus)", got)
	}
}

func TestEditInsertsAtABlockBoundary(t *testing.T) {
	text := Prose(4 * KB)
	at := MidPoint(text)
	if text[at-2:at] != "\n\n" {
		t.Fatalf("MidPoint %d is not after a blank line", at)
	}
	if got := Edit(text, "x"); len(got) != len(text)+1 || got[at] != 'x' {
		t.Fatal("Edit did not insert at the midpoint")
	}
}
