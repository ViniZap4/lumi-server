package wsync

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fws "github.com/fasthttp/websocket"
	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/crdt"
	"github.com/ViniZap4/lumi-server/internal/domain"
)

// epochTable is a mutable note → crdt_epoch lookup for the handler.
type epochTable struct {
	mu sync.Mutex
	m  map[string]string
}

func (e *epochTable) set(note, epoch string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.m[note] = epoch
}

func (e *epochTable) lookup(_ context.Context, _ uuid.UUID, note string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if v, ok := e.m[note]; ok {
		return v, nil
	}
	return "", domain.ErrNotFound
}

// dialTicketReason is dialTicket that also returns the close reason.
func (e *ticketEnv) dialTicketReason(t *testing.T, note, ticket string) (int, string) {
	t.Helper()
	url := e.base + "/api/vaults/" + e.vault.String() + "/notes/" + note + "/sync?ticket=" + ticket
	conn, _, err := (&fws.Dialer{HandshakeTimeout: 2 * time.Second}).Dial(url, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := conn.ReadMessage(); err != nil {
		var ce *fws.CloseError
		if errors.As(err, &ce) {
			return ce.Code, ce.Text
		}
		t.Fatalf("read: %v", err)
	}
	return 0, ""
}

// ws-ticket carries the note's crdt_epoch, and a ticket whose note
// changed lineage between mint and upgrade is refused with 4401
// ticket_stale (the client re-mints and learns the new epoch).
func TestTicket_CarriesEpochAndRefusesStaleLineage(t *testing.T) {
	env, _, _ := newTicketFixture(t)
	epochs := &epochTable{m: map[string]string{"n1": "e1", "n2": "x"}}
	env.handler.SetEpochLookup(epochs.lookup)

	status, tr := env.mint(t, "alice", "n1")
	if status != http.StatusCreated || tr.CRDTEpoch != "e1" {
		t.Fatalf("mint: status %d epoch %q, want 201 e1", status, tr.CRDTEpoch)
	}
	// Mint pre-warms the room so lazy init settles the epoch before join.
	if env.hub.RoomIfActive(env.vault, "n1") == nil {
		t.Fatal("ws-ticket did not pre-warm the note's room")
	}
	if code, _ := env.dialTicketReason(t, "n1", tr.Ticket); code != 0 {
		t.Fatalf("same-lineage upgrade closed %d", code)
	}

	_, tr = env.mint(t, "alice", "n1")
	epochs.set("n1", "e2") // delete+recreate (or reseed) after the mint
	if code, reason := env.dialTicketReason(t, "n1", tr.Ticket); code != CloseUnauthorized || reason != "ticket_stale" {
		t.Fatalf("stale-lineage upgrade: %d %q, want 4401 ticket_stale", code, reason)
	}

	status, tr = env.mint(t, "alice", "n1")
	if status != http.StatusCreated || tr.CRDTEpoch != "e2" {
		t.Fatalf("re-mint: status %d epoch %q, want e2", status, tr.CRDTEpoch)
	}
	if code, _ := env.dialTicketReason(t, "n1", tr.Ticket); code != 0 {
		t.Fatalf("re-minted upgrade closed %d", code)
	}
}

// Deleting a note (Hub.DropNote) ends its live sockets with 4404.
func TestDropNote_ClosesLiveSocketWith4404(t *testing.T) {
	env, _, _ := newTicketFixture(t)
	_, tr := env.mint(t, "alice", "n1")
	url := env.base + "/api/vaults/" + env.vault.String() + "/notes/n1/sync?ticket=" + tr.Ticket
	conn, _, err := (&fws.Dialer{HandshakeTimeout: 2 * time.Second}).Dial(url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := conn.ReadMessage(); err != nil { // SyncStep1
		t.Fatal(err)
	}
	env.hub.DropNote(env.vault, "n1", CloseNotFound, "note_deleted")
	for {
		if _, _, err = conn.ReadMessage(); err != nil {
			break
		}
	}
	var ce *fws.CloseError
	if !errors.As(err, &ce) || ce.Code != CloseNotFound || ce.Text != "note_deleted" {
		t.Fatalf("got %v, want close 4404 note_deleted", err)
	}
}

// DropNote ends the room's history: subscribers are closed with the code,
// a pending debounced mirror is discarded (the file now belongs to a
// deleted or recreated note), and the next acquirer loads a new room.
func TestDropNote_DiscardsRoomAndPendingMirror(t *testing.T) {
	var mirrors atomic.Int32
	hub := NewHub(crdt.NewRegistry(newMemRepo()),
		WithMirrorDebounce(30*time.Millisecond),
		WithFSMirror(func(context.Context, uuid.UUID, string, string) error {
			mirrors.Add(1)
			return nil
		}))
	defer hub.Close()
	ctx := context.Background()
	vault, note := uuid.New(), "n"

	sub := hub.NewSubscriber(uuid.New())
	room, err := hub.Join(ctx, vault, note, sub)
	if err != nil {
		t.Fatal(err)
	}
	if err := room.ApplyAndBroadcast(clientUpdate(t, room, "old lineage"), nil, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	hub.DropNote(vault, note, CloseNotFound, "note_deleted")

	select {
	case <-sub.Done:
	case <-time.After(time.Second):
		t.Fatal("subscriber not closed")
	}
	if code, reason := sub.CloseCode(); code != CloseNotFound || reason != "note_deleted" {
		t.Fatalf("close code %d %q", code, reason)
	}
	if hub.RoomIfActive(vault, note) != nil {
		t.Fatal("dropped room still registered")
	}
	if _, err := room.applyUpdate(clientUpdate(t, room, "late"), nil, ApplyOptions{}); err == nil {
		t.Fatal("write to a dropped room succeeded")
	}
	hub.Leave(room, sub) // last holder: shuts the dropped room down

	time.Sleep(80 * time.Millisecond)
	if n := mirrors.Load(); n != 0 {
		t.Fatalf("dropped room mirrored %d times; must discard its pending mirror", n)
	}

	sub2 := hub.NewSubscriber(uuid.New())
	room2, err := hub.Join(ctx, vault, note, sub2)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Leave(room2, sub2)
	if room2 == room {
		t.Fatal("join after DropNote reused the dropped room")
	}
}

// A holder already inside View keeps a usable doc while DropNote runs;
// the doc is closed only when that holder releases it.
func TestDropNote_WaitsForInFlightHolder(t *testing.T) {
	repo := newMemRepo()
	hub := NewHub(crdt.NewRegistry(repo))
	defer hub.Close()
	vault, note := uuid.New(), "n"
	seed := crdt.NewDoc()
	_, _ = seed.ApplyTextDiff("body", "x")
	st, _ := seed.EncodeStateAsUpdate()
	seed.Close()
	_ = repo.UpsertSnapshot(context.Background(), vault, note, st)

	entered, proceed := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- hub.View(context.Background(), vault, note, func(d *crdt.Doc) error {
			close(entered)
			<-proceed
			txt, err := d.Text()
			if err == nil && txt != "body" {
				err = errors.New("doc text " + txt)
			}
			return err
		})
	}()
	<-entered
	hub.DropNote(vault, note, CloseNotFound, "note_deleted")
	close(proceed)
	if err := <-done; err != nil {
		t.Fatalf("in-flight view: %v", err)
	}
}

// Prewarm loads the room and leaves it lingering for the join.
func TestPrewarmLeavesRoomActive(t *testing.T) {
	hub := NewHub(crdt.NewRegistry(newMemRepo()), WithIdleTTL(time.Minute))
	defer hub.Close()
	vault := uuid.New()
	if err := hub.Prewarm(context.Background(), vault, "n"); err != nil {
		t.Fatal(err)
	}
	if hub.RoomIfActive(vault, "n") == nil {
		t.Fatal("prewarmed room not active")
	}
}
