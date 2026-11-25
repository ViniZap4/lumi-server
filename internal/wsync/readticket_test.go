package wsync

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	fws "github.com/fasthttp/websocket"
	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/crdt"
	"github.com/ViniZap4/lumi-server/internal/domain"
)

func (e *ticketEnv) mintMode(t *testing.T, token, note, body string) (int, ticketResponse) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost,
		"http"+e.base[2:]+"/api/vaults/"+e.vault.String()+"/notes/"+note+"/ws-ticket", strings.NewReader(body))
	req.Header.Set("X-Lumi-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out ticketResponse
	if resp.StatusCode == http.StatusCreated {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
	}
	return resp.StatusCode, out
}

func (e *ticketEnv) open(t *testing.T, note, ticket string) *fws.Conn {
	t.Helper()
	url := e.base + "/api/vaults/" + e.vault.String() + "/notes/" + note + "/sync?ticket=" + ticket
	conn, _, err := (&fws.Dialer{HandshakeTimeout: 2 * time.Second}).Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("first read: %v", err)
	}
	if m, _ := DecodeMessage(msg); m.SyncSub != SyncStep1 {
		t.Fatalf("first frame %+v", m)
	}
	return conn
}

func readUntilClose(t *testing.T, conn *fws.Conn) int {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			var ce *fws.CloseError
			if errors.As(err, &ce) {
				return ce.Code
			}
			return -1
		}
	}
}

// §A6.2 (M2): a Viewer (note.read only) mints a read ticket, joins, gets
// live updates; a no-op Step2 is tolerated; an update that would change
// the doc closes the socket 4403 read_only and changes nothing.
func TestTicket_ReadMode(t *testing.T) {
	alice, viewer := uuid.New(), uuid.New()
	env := startTicketServer(t,
		map[string]uuid.UUID{"alice": alice, "viewer": viewer, "stranger": uuid.New()},
		stubResolver{alice: {domain.CapNoteEdit, domain.CapNoteRead}, viewer: {domain.CapNoteRead}},
		map[string]bool{"n1": true})

	if st, _ := env.mintMode(t, "viewer", "n1", ``); st != http.StatusForbidden {
		t.Fatalf("viewer edit ticket: %d", st)
	}
	if st, _ := env.mintMode(t, "viewer", "n1", `{"mode":"write"}`); st != http.StatusBadRequest {
		t.Fatalf("bad mode: %d", st)
	}
	if st, _ := env.mintMode(t, "stranger", "n1", `{"mode":"read"}`); st != http.StatusForbidden {
		t.Fatalf("stranger read ticket: %d", st)
	}
	st, tr := env.mintMode(t, "viewer", "n1", `{"mode":"read"}`)
	if st != http.StatusCreated || tr.Mode != ModeRead {
		t.Fatalf("viewer read ticket: %d %+v", st, tr)
	}
	if _, er := env.mintMode(t, "alice", "n1", ``); er.Mode != ModeEdit {
		t.Fatalf("default mode %q", er.Mode)
	}

	conn := env.open(t, "n1", tr.Ticket)
	// A fresh client's [0,0] Step2 is fine.
	if err := conn.WriteMessage(fws.BinaryMessage, EncodeSyncStep2([]byte{0, 0})); err != nil {
		t.Fatal(err)
	}
	// A live edit made elsewhere reaches the reader.
	doc := crdt.NewDoc()
	upd, err := doc.ApplyTextDiff("hello from alice", "test")
	doc.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.hub.ApplyUpdate(t.Context(), env.vault, "n1", upd, ApplyOptions{Origin: OriginLive}); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := false
	for !got {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			t.Fatalf("reader got no live update: %v", err)
		}
		if m, _ := DecodeMessage(msg); m.Type == MessageSync && m.SyncSub == SyncUpdate {
			got = true
		}
	}
	// The reader tries to write: closed, nothing applied.
	forged := crdt.NewDoc()
	evil, _ := forged.ApplyTextDiff("forged", "evil")
	forged.Close()
	if err := conn.WriteMessage(fws.BinaryMessage, EncodeSyncUpdate(evil)); err != nil {
		t.Fatal(err)
	}
	if code := readUntilClose(t, conn); code != CloseForbidden {
		t.Fatalf("close code %d, want %d", code, CloseForbidden)
	}
	var text string
	_ = env.hub.View(t.Context(), env.vault, "n1", func(d *crdt.Doc) error {
		var err error
		text, err = d.Text()
		return err
	})
	if text != "hello from alice" {
		t.Fatalf("doc after forged update = %q", text)
	}
}
