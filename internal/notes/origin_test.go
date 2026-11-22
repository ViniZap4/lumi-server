package notes

import (
	"errors"
	"testing"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

func TestClientOrigin(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"", "tui-diff", true},
		{"  ", "tui-diff", true},
		{"tui-diff", "tui-diff", true},
		{"apple-diff", "apple-diff", true},
		{" web ", "web", true},
		{"web-diff", "web-diff", true},
		// Regression: clients could claim server-internal origins and
		// suppress federation fan-out or impersonate the fs watcher.
		{"federation:https://peer.example", "", false},
		{"federation:", "", false},
		{"fs-watcher", "", false},
		{"anything-else", "", false},
	}
	for _, tc := range cases {
		got, err := clientOrigin(tc.in)
		if tc.ok {
			if err != nil || got != tc.want {
				t.Errorf("clientOrigin(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
			}
			continue
		}
		if !errors.Is(err, domain.ErrValidation) {
			t.Errorf("clientOrigin(%q) = %q, %v; want ErrValidation", tc.in, got, err)
		}
	}
}
