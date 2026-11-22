package wsync

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/crdt"
)

// Golden bytes produced by the reference implementation (yjs 13.6 +
// y-protocols awareness.js from web-client/node_modules):
//
//	a.setLocalState({user:{name:'A'}}); a.setLocalState({user:{name:'B'}})
//	encodeAwarenessUpdate(a,[1])            → goldenState
//	a.setLocalState(null); encode…           → goldenLeave
//	framed: writeVarUint(1)+writeVarUint8Array → goldenFramedLeave
//	clientID 3000000000 after 201 changes    → goldenLeaveBigID
const (
	goldenState       = "010102157b2275736572223a7b226e616d65223a2242227d7d"
	goldenLeave       = "010103046e756c6c"
	goldenFramedLeave = "0108010103046e756c6c"
	goldenLeaveBigID  = "0180bcc1960bc901046e756c6c"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// S8: numbering must match y-websocket (messageSync=0, messageAwareness=1,
// messageAuth=2, messageQueryAwareness=3).
func TestMessageNumberingMatchesYWebsocket(t *testing.T) {
	if MessageSync != 0 || MessageAwareness != 1 || MessageAuth != 2 || MessageQueryAwareness != 3 {
		t.Fatalf("numbering = %d/%d/%d/%d", MessageSync, MessageAwareness, MessageAuth, MessageQueryAwareness)
	}
	m, err := DecodeMessage([]byte{3})
	if err != nil || m.Type != MessageQueryAwareness {
		t.Fatalf("query-awareness frame parsed as %+v (%v)", m, err)
	}
	// y-protocols auth "permission denied": [2, 0, varString(reason)]
	m, err = DecodeMessage([]byte{2, 0, 1, 'x'})
	if err != nil || m.Type != MessageAuth {
		t.Fatalf("auth frame parsed as %+v (%v)", m, err)
	}
}

func TestAwarenessCodecGolden(t *testing.T) {
	entries, err := DecodeAwarenessUpdate(mustHex(t, goldenState))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ClientID != 1 || entries[0].Clock != 2 || entries[0].State != `{"user":{"name":"B"}}` {
		t.Fatalf("decoded %+v", entries)
	}
	if got := hex.EncodeToString(EncodeAwarenessUpdate(entries)); got != goldenState {
		t.Fatalf("re-encode %s", got)
	}
	leave := EncodeAwarenessUpdate([]AwarenessEntry{{ClientID: 1, Clock: 3, State: "null"}})
	if hex.EncodeToString(leave) != goldenLeave {
		t.Fatalf("leave = %x", leave)
	}
	if got := hex.EncodeToString(EncodeAwareness(leave)); got != goldenFramedLeave {
		t.Fatalf("framed leave = %s", got)
	}
	big := EncodeAwarenessUpdate([]AwarenessEntry{{ClientID: 3000000000, Clock: 201, State: "null"}})
	if hex.EncodeToString(big) != goldenLeaveBigID {
		t.Fatalf("big-id leave = %x", big)
	}
	for _, bad := range []string{"", "01", "0101", "010102ff", "010103046e756c6c00"} {
		if _, err := DecodeAwarenessUpdate(mustHex(t, bad)); err == nil {
			t.Errorf("malformed %q accepted", bad)
		}
	}
}

// S7: when a y-protocols subscriber leaves, peers get a valid awareness
// update retiring its client (clock+1, state null) — byte-identical to
// what y-protocols' removeAwarenessStates emits — never JSON.
func TestLeaveEmitsValidAwarenessRemoval(t *testing.T) {
	hub := NewHub(crdt.NewRegistry(newMemRepo()))
	defer hub.Close()
	v := uuid.New()
	leaver := hub.NewSubscriberWithClient(uuid.New(), uuid.New())
	observer := hub.NewSubscriber(uuid.New())
	room, err := hub.Join(context.Background(), v, "n", leaver)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hub.Join(context.Background(), v, "n", observer); err != nil {
		t.Fatal(err)
	}
	defer hub.Leave(room, observer)

	room.handleAwareness(mustHex(t, goldenState), leaver)
	if msg := <-observer.Out; hex.EncodeToString(msg) != "0119"+goldenState {
		t.Fatalf("relay = %x", msg)
	}
	// The observer re-broadcasts the same state (y-websocket does); that
	// must not steal ownership.
	room.handleAwareness(mustHex(t, goldenState), observer)
	<-leaver.Out

	hub.Leave(room, leaver)
	select {
	case msg := <-observer.Out:
		if got := hex.EncodeToString(msg); got != goldenFramedLeave {
			t.Fatalf("leave frame = %s, want %s", got, goldenFramedLeave)
		}
	case <-time.After(time.Second):
		t.Fatal("no awareness removal broadcast")
	}
	select {
	case msg := <-observer.Out:
		t.Fatalf("unexpected extra frame (legacy JSON to a y-protocols peer?): %q", msg)
	case <-time.After(30 * time.Millisecond):
	}
}

func TestQueryAwarenessRepliesWithRegister(t *testing.T) {
	hub := NewHub(crdt.NewRegistry(newMemRepo()))
	defer hub.Close()
	v := uuid.New()
	a, b := hub.NewSubscriber(uuid.New()), hub.NewSubscriber(uuid.New())
	room, _ := hub.Join(context.Background(), v, "n", a)
	defer hub.Leave(room, a)
	room.handleAwareness(mustHex(t, goldenState), a)
	_, _ = hub.Join(context.Background(), v, "n", b)
	defer hub.Leave(room, b)
	room.queryAwareness(b)
	if msg := <-b.Out; hex.EncodeToString(msg) != "0119"+goldenState {
		t.Fatalf("query reply = %x", msg)
	}
}

func TestLegacyJSONAwarenessNotSentToYjsPeers(t *testing.T) {
	hub := NewHub(crdt.NewRegistry(newMemRepo()))
	defer hub.Close()
	v := uuid.New()
	apple, web := hub.NewSubscriber(uuid.New()), hub.NewSubscriber(uuid.New())
	room, _ := hub.Join(context.Background(), v, "n", apple)
	defer hub.Leave(room, apple)
	_, _ = hub.Join(context.Background(), v, "n", web)
	defer hub.Leave(room, web)
	room.handleAwareness(mustHex(t, goldenState), web) // web speaks y-protocols
	<-apple.Out                                        // unknown dialect still gets lib0
	room.handleAwareness([]byte(`{"client_id":"x"}`), apple)
	select {
	case msg := <-web.Out:
		t.Fatalf("JSON presence leaked to y-protocols peer: %q", msg)
	case <-time.After(30 * time.Millisecond):
	}
	room.handleAwareness([]byte("garbage"), apple) // dropped
}
