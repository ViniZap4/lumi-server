package feed

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
)

// startSpikeServer runs a real Fiber listener (app.Test bypasses the
// fasthttp connection loop, which is where WriteTimeout lives).
func startSpikeServer(t *testing.T, writeTimeout time.Duration, h fiber.Handler) string {
	t.Helper()
	app := fiber.New(fiber.Config{DisableStartupMessage: true, WriteTimeout: writeTimeout})
	app.Get("/stream", h)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = app.Listener(ln) }()
	t.Cleanup(func() { _ = app.Shutdown() })
	return "http://" + ln.Addr().String() + "/stream"
}

func streamPings(n int, every, grace time.Duration) fiber.Handler {
	return func(c *fiber.Ctx) error {
		conn := c.Context().Conn()
		c.Set("Content-Type", "text/event-stream")
		c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
			fw := newFrameWriter(w, conn, grace)
			for i := 0; i < n; i++ {
				if err := fw.ping(); err != nil {
					return
				}
				time.Sleep(every)
			}
		})
		return nil
	}
}

func countPings(t *testing.T, url string) int {
	t.Helper()
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body) // a cut stream ends in an error; count what arrived
	return strings.Count(string(body), ": ping\n\n")
}

// S0: with a sliding write deadline the stream outlives WriteTimeout by
// far (here 12 pings over ~1.2 s against a 300 ms WriteTimeout — the same
// ratio as the production 25 s ping against 60 s, scaled down).
func TestS0_SlidingDeadlineOutlivesWriteTimeout(t *testing.T) {
	url := startSpikeServer(t, 300*time.Millisecond, streamPings(12, 100*time.Millisecond, 250*time.Millisecond))
	if got := countPings(t, url); got != 12 {
		t.Fatalf("got %d pings, want 12: stream was cut despite deadline refresh", got)
	}
}

// S0 control: without the refresh, fasthttp's WriteTimeout is absolute and
// kills the stream. If this ever starts passing all pings, fasthttp changed
// semantics and the sliding deadline can be revisited.
func TestS0_AbsoluteWriteTimeoutCutsStream(t *testing.T) {
	url := startSpikeServer(t, 300*time.Millisecond, streamPings(12, 100*time.Millisecond, 0))
	if got := countPings(t, url); got >= 12 {
		t.Fatalf("got %d pings: WriteTimeout no longer cuts long streams", got)
	}
}

// S0: Response.Body() drains a body stream — the reason middleware must
// check IsBodyStream before touching the body.
func TestS0_BodyDrainsStream(t *testing.T) {
	app := fiber.New()
	drained := make(chan int, 1)
	app.Use(func(c *fiber.Ctx) error {
		err := c.Next()
		if c.Response().IsBodyStream() {
			drained <- len(c.Response().Body())
		}
		return err
	})
	app.Get("/s", streamPings(3, time.Millisecond, 0))
	resp, err := app.Test(mustReq(t, "/s"), 5000)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if n := <-drained; n != 3*len(": ping\n\n") {
		t.Fatalf("Body() returned %d bytes; expected the whole drained stream", n)
	}
}

func mustReq(t *testing.T, path string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://example.test"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}
