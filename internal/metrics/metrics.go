// Package metrics is lumi's opt-in Prometheus exposition
// (docs/SPEC-ESPELHO-SELADO.md §A14). It is off unless LUMI_METRICS_ADDR
// is set, and then served on its own listener (bind it to loopback).
//
// Counters are process-wide atomics, cheap enough for hot paths (relay
// frames). Gauges come from a collector run at scrape time. No label ever
// carries a note id or a user id; a vault id appears only on mirror gauges
// and only when LUMI_METRICS_VAULT_LABELS=true (else gauges are summed
// across vaults, or maxed for ages).
package metrics

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Counter is a monotonically increasing value.
type Counter struct{ v atomic.Int64 }

func (c *Counter) Inc() { c.v.Add(1) }

func (c *Counter) Add(n int64) {
	if n > 0 {
		c.v.Add(n)
	}
}

func (c *Counter) Value() int64 { return c.v.Load() }

// Process-wide counters.
var (
	MirrorViolation          Counter
	MirrorDivergent          Counter
	MirrorLocalWriteBlocked  Counter
	MirrorIntegrityRewritten Counter
)

// LabeledCounter is a counter family keyed by label values.
type LabeledCounter struct {
	labels []string
	m      sync.Map // joined values → *Counter
}

func newLabeled(labels ...string) *LabeledCounter { return &LabeledCounter{labels: labels} }

// With returns the counter of the given label values (len = labels).
func (l *LabeledCounter) With(values ...string) *Counter {
	key := strings.Join(values, "\x00")
	if c, ok := l.m.Load(key); ok {
		return c.(*Counter)
	}
	c, _ := l.m.LoadOrStore(key, &Counter{})
	return c.(*Counter)
}

func (l *LabeledCounter) each(fn func(values []string, v int64)) {
	type row struct {
		values []string
		v      int64
	}
	var rows []row
	l.m.Range(func(k, c any) bool {
		rows = append(rows, row{strings.Split(k.(string), "\x00"), c.(*Counter).Value()})
		return true
	})
	sort.Slice(rows, func(i, j int) bool { return strings.Join(rows[i].values, ",") < strings.Join(rows[j].values, ",") })
	for _, r := range rows {
		fn(r.values, r.v)
	}
}

// Labeled counter families.
var (
	RelayFrames     = newLabeled("dir", "type")
	RelayBytes      = newLabeled("dir")
	PublishRequests = newLabeled("status")
)

// Sample is one gauge value.
type Sample struct {
	Name   string
	Help   string
	Labels [][2]string
	Value  float64
}

// Collector returns the gauges at scrape time.
type Collector func(ctx context.Context) []Sample

var (
	collMu     sync.Mutex
	collectors []Collector
)

// Register adds a gauge collector.
func Register(c Collector) {
	collMu.Lock()
	collectors = append(collectors, c)
	collMu.Unlock()
}

func counterHelp() map[string]string {
	return map[string]string{
		"lumi_mirror_violation_total":           "Content frames a mirror sent to home (link closed).",
		"lumi_mirror_divergent_total":           "Mirror copies whose state vector was not dominated by home's.",
		"lumi_mirror_local_write_blocked_total": "Local writes refused on a mirror vault.",
		"lumi_mirror_integrity_rewritten_total": "Files rewritten by the mirror integrity pass.",
		"lumi_relay_frames_total":               "Federation relay frames by direction and type.",
		"lumi_relay_bytes_total":                "Federation relay bytes by direction.",
		"lumi_publish_requests_total":           "Anonymous publish requests by HTTP status.",
	}
}

// Write renders every metric in the Prometheus text format (0.0.4).
func Write(ctx context.Context, w io.Writer) error {
	help := counterHelp()
	var b strings.Builder
	simple := func(name string, c *Counter) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help[name], name, name, c.Value())
	}
	simple("lumi_mirror_violation_total", &MirrorViolation)
	simple("lumi_mirror_divergent_total", &MirrorDivergent)
	simple("lumi_mirror_local_write_blocked_total", &MirrorLocalWriteBlocked)
	simple("lumi_mirror_integrity_rewritten_total", &MirrorIntegrityRewritten)
	family := func(name string, l *LabeledCounter) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s counter\n", name, help[name], name)
		l.each(func(values []string, v int64) {
			pairs := make([][2]string, len(values))
			for i := range values {
				pairs[i] = [2]string{l.labels[i], values[i]}
			}
			fmt.Fprintf(&b, "%s%s %d\n", name, labelString(pairs), v)
		})
	}
	family("lumi_relay_frames_total", RelayFrames)
	family("lumi_relay_bytes_total", RelayBytes)
	family("lumi_publish_requests_total", PublishRequests)

	collMu.Lock()
	cs := append([]Collector(nil), collectors...)
	collMu.Unlock()
	var samples []Sample
	for _, c := range cs {
		samples = append(samples, c(ctx)...)
	}
	sort.SliceStable(samples, func(i, j int) bool { return samples[i].Name < samples[j].Name })
	seen := map[string]bool{}
	for _, s := range samples {
		if !seen[s.Name] {
			seen[s.Name] = true
			fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n", s.Name, s.Help, s.Name)
		}
		fmt.Fprintf(&b, "%s%s %s\n", s.Name, labelString(s.Labels), strconv.FormatFloat(s.Value, 'g', -1, 64))
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func labelString(pairs [][2]string) string {
	if len(pairs) == 0 {
		return ""
	}
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p[0] + `="` + escape(p[1]) + `"`
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func escape(v string) string {
	return strings.NewReplacer(`\`, `\\`, "\n", `\n`, `"`, `\"`).Replace(v)
}

// Handler serves GET /metrics.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = Write(ctx, w)
	})
	return mux
}

// Serve runs the metrics listener on addr until ctx ends.
func Serve(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
