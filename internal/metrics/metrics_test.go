package metrics

import (
	"context"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWrite_PrometheusText(t *testing.T) {
	MirrorDivergent.Inc()
	RelayFrames.With("in", "note_sync").Add(3)
	PublishRequests.With("404").Inc()
	Register(func(context.Context) []Sample {
		return []Sample{
			{Name: "lumi_federation_links", Help: "h", Labels: [][2]string{{"mode", "mirror"}, {"role", "home"}, {"status", "active"}}, Value: 2},
			{Name: "lumi_mirror_lag_seq", Help: "lag", Value: 5},
		}
	})
	srv := httptest.NewServer(Handler())
	defer srv.Close()
	resp, err := srv.Client().Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	out := string(b)
	for _, want := range []string{
		"# TYPE lumi_mirror_divergent_total counter\nlumi_mirror_divergent_total 1\n",
		`lumi_relay_frames_total{dir="in",type="note_sync"} 3`,
		`lumi_publish_requests_total{status="404"} 1`,
		"# TYPE lumi_federation_links gauge\n",
		`lumi_federation_links{mode="mirror",role="home",status="active"} 2`,
		"lumi_mirror_lag_seq 5",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Fatalf("content type %q", ct)
	}
	if escape("a\"b\\c\n") != `a\"b\\c\n` {
		t.Fatal("label escaping")
	}
}
