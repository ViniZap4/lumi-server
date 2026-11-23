package domain

import "testing"

func TestNewCRDTEpochUniqueHex(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		e := NewCRDTEpoch()
		if len(e) != 32 {
			t.Fatalf("len %d, want 32: %q", len(e), e)
		}
		for _, c := range e {
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				t.Fatalf("non-hex char in %q", e)
			}
		}
		if seen[e] {
			t.Fatalf("duplicate epoch %q", e)
		}
		seen[e] = true
	}
}
