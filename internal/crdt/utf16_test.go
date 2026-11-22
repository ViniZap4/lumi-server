package crdt

import "testing"

// Regression: yffi defaults to UTF-8 byte offsets while ApplyTextDiff
// computes UTF-16 offsets, so every non-ASCII edit hit the wrong range.
func TestApplyTextDiff_NonASCIIOffsets(t *testing.T) {
	cases := []struct{ from, to string }{
		{"a😀b", "a😁b"}, // vector V12: surrogate pair replaced whole
		{"café au lait", "café noir"},
		{"ação é boa", "ação foi boa"},
		{"😀😀", "😀x😀"},
	}
	for _, tc := range cases {
		d := NewDoc()
		if _, err := d.ApplyTextDiff(tc.from, "seed"); err != nil {
			t.Fatal(err)
		}
		if _, err := d.ApplyTextDiff(tc.to, "edit"); err != nil {
			t.Fatal(err)
		}
		got, _ := d.Text()
		d.Close()
		if got != tc.to {
			t.Errorf("%q → %q: got %q", tc.from, tc.to, got)
		}
	}
}
