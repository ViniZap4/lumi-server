package feed

import (
	"bufio"
	"net"
	"time"
)

// SSE transport over fasthttp (S0 spike, SPEC-LIVROS §6).
//
// Findings that shape this file:
//
//  1. fasthttp's Server.WriteTimeout is an ABSOLUTE deadline: serveConn
//     calls conn.SetWriteDeadline(now+WriteTimeout) once, right before the
//     response is written, and never refreshes it while a body stream is
//     being copied. With the server's 60 s WriteTimeout a stream dies at
//     t≈60 s with an i/o timeout. Lowering the stream lifetime to 50 s
//     (the spec's fallback) is unnecessary: the stream writer refreshes the
//     deadline itself before every flush (sliding deadline). net.Conn
//     deadlines are goroutine-safe, so setting it from the stream-writer
//     goroutine while the server goroutine copies the pipe is fine.
//  2. Response.Body() DRAINS a body stream. Any middleware that calls it
//     after c.Next() (the access log did, for its byte count) blocks until
//     the stream ends and buffers it all in memory — SSE never reaches the
//     client. Middleware must check Response.IsBodyStream() first.
//  3. SetBodyStreamWriter runs the writer in its own goroutine behind an
//     in-memory pipe; a disconnected client is only noticed on the next
//     Flush. The 25 s ping bounds that detection time.

// deadliner is the subset of net.Conn the stream needs.
type deadliner interface {
	SetWriteDeadline(t time.Time) error
}

// frameWriter writes SSE frames and keeps the connection's write deadline
// sliding ahead of every flush.
type frameWriter struct {
	w     *bufio.Writer
	conn  deadliner // nil in unit tests
	grace time.Duration
	now   func() time.Time
}

func newFrameWriter(w *bufio.Writer, conn net.Conn, grace time.Duration) *frameWriter {
	fw := &frameWriter{w: w, grace: grace, now: time.Now}
	if conn != nil {
		fw.conn = conn
	}
	return fw
}

// event writes `event: <name>\ndata: <data>\n\n` and flushes. data must be
// a single line (json.Marshal output never contains raw newlines).
func (f *frameWriter) event(name string, data []byte) error {
	_, _ = f.w.WriteString("event: ")
	_, _ = f.w.WriteString(name)
	_, _ = f.w.WriteString("\ndata: ")
	_, _ = f.w.Write(data)
	_, _ = f.w.WriteString("\n\n")
	return f.flush()
}

// ping writes the `: ping` comment frame and flushes.
func (f *frameWriter) ping() error {
	_, _ = f.w.WriteString(": ping\n\n")
	return f.flush()
}

func (f *frameWriter) flush() error {
	if f.conn != nil && f.grace > 0 {
		_ = f.conn.SetWriteDeadline(f.now().Add(f.grace))
	}
	return f.w.Flush()
}
