package pg

import "testing"

func TestLikePattern(t *testing.T) {
	cases := map[string]string{"": "", "ali": "%ali%", "50%_off": `%50\%\_off%`, `a\b`: `%a\\b%`}
	for in, want := range cases {
		if got := likePattern(in); got != want {
			t.Errorf("likePattern(%q) = %q, want %q", in, got, want)
		}
	}
	if got := escapeLike("auth.login_"); got != `auth.login\_` {
		t.Errorf("escapeLike = %q", got)
	}
}
