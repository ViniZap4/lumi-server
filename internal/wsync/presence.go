package wsync

import (
	"encoding/json"
	"errors"
	"sync/atomic"
	"unicode/utf8"

	"github.com/google/uuid"
)

// Awareness handling (CRDT client protocol §10 S7).
//
// y-protocols clients (web/y-websocket) send lib0 awareness updates. The
// server keeps a small per-room register (clientID → clock, state, the
// subscriber that originated it), like the reference y-websocket server,
// so that when a subscriber leaves it can broadcast a VALID awareness
// update that retires its clients (clock+1, state null) and so it can
// answer QueryAwareness.
//
// The legacy Apple client sends a JSON PresenceState object inside the
// awareness frame instead. JSON frames are relayed only to other legacy
// subscribers, and lib0 frames only to non-legacy ones, so neither
// dialect receives a payload it cannot decode. The legacy JSON "left"
// frame is likewise sent only to legacy subscribers.

const (
	dialectUnknown int32 = iota
	dialectYjs
	dialectLegacyJSON
)

// maxAwarenessClients bounds the per-room register.
const maxAwarenessClients = 1024

// awarenessTracker records the awareness dialect a subscriber speaks.
type awarenessTracker struct {
	dialect atomic.Int32
}

type awEntry struct {
	clock uint64
	state string // JSON text; "null" means removed
	owner *Subscriber
}

// AwarenessEntry is one decoded record of a y-protocols awareness update.
type AwarenessEntry struct {
	ClientID uint64
	Clock    uint64
	State    string // JSON; "null" = client removed
}

var errBadAwareness = errors.New("wsync: malformed awareness update")

// DecodeAwarenessUpdate parses a lib0 awareness update. It must consume
// the whole buffer.
func DecodeAwarenessUpdate(b []byte) ([]AwarenessEntry, error) {
	n, off, err := readVarUint(b)
	if err != nil {
		return nil, errBadAwareness
	}
	if n > uint64(len(b)) {
		return nil, errBadAwareness
	}
	out := make([]AwarenessEntry, 0, n)
	for i := uint64(0); i < n; i++ {
		client, k, err := readVarUint(b[off:])
		if err != nil {
			return nil, errBadAwareness
		}
		off += k
		clock, k, err := readVarUint(b[off:])
		if err != nil {
			return nil, errBadAwareness
		}
		off += k
		state, k, err := readVarBytes(b[off:])
		if err != nil || !utf8.Valid(state) {
			return nil, errBadAwareness
		}
		off += k
		out = append(out, AwarenessEntry{ClientID: client, Clock: clock, State: string(state)})
	}
	if off != len(b) {
		return nil, errBadAwareness
	}
	return out, nil
}

// EncodeAwarenessUpdate is the inverse of DecodeAwarenessUpdate.
func EncodeAwarenessUpdate(entries []AwarenessEntry) []byte {
	out := writeVarUint(nil, uint64(len(entries)))
	for _, e := range entries {
		out = writeVarUint(out, e.ClientID)
		out = writeVarUint(out, e.Clock)
		out = writeVarBytes(out, []byte(e.State))
	}
	return out
}

// handleAwareness records and relays an inbound awareness frame body.
func (r *Room) handleAwareness(body []byte, from *Subscriber) {
	if entries, err := DecodeAwarenessUpdate(body); err == nil {
		from.aw.dialect.CompareAndSwap(dialectUnknown, dialectYjs)
		r.recordAwareness(entries, from)
		r.broadcastFiltered(EncodeAwareness(body), from, func(s *Subscriber) bool {
			return s.aw.dialect.Load() != dialectLegacyJSON
		})
		return
	}
	if len(body) > 0 && body[0] == '{' && json.Valid(body) {
		from.aw.dialect.CompareAndSwap(dialectUnknown, dialectLegacyJSON)
		r.broadcastFiltered(EncodeAwareness(body), from, func(s *Subscriber) bool {
			return s.aw.dialect.Load() == dialectLegacyJSON
		})
		return
	}
	// Neither dialect: drop rather than poison peers' decoders.
}

func (r *Room) recordAwareness(entries []AwarenessEntry, from *Subscriber) {
	r.awMu.Lock()
	defer r.awMu.Unlock()
	if r.aw == nil {
		r.aw = map[uint64]*awEntry{}
	}
	for _, e := range entries {
		cur, ok := r.aw[e.ClientID]
		if ok && e.Clock <= cur.clock {
			continue // relay of a state we already have
		}
		if !ok && len(r.aw) >= maxAwarenessClients {
			continue
		}
		if e.State == "null" {
			delete(r.aw, e.ClientID)
			continue
		}
		// The first subscriber to deliver a newer clock is the
		// originator: peers re-broadcasting it carry the same clock.
		r.aw[e.ClientID] = &awEntry{clock: e.Clock, state: e.State, owner: from}
	}
}

// queryAwareness answers a QueryAwareness with every known state.
func (r *Room) queryAwareness(to *Subscriber) {
	r.awMu.Lock()
	entries := make([]AwarenessEntry, 0, len(r.aw))
	for id, e := range r.aw {
		entries = append(entries, AwarenessEntry{ClientID: id, Clock: e.clock, State: e.state})
	}
	r.awMu.Unlock()
	if len(entries) == 0 {
		return
	}
	select {
	case to.Out <- EncodeAwareness(EncodeAwarenessUpdate(entries)):
	default:
	}
}

// broadcastPresenceLeave retires the departed subscriber's awareness
// clients: a y-protocols update with clock+1 and state null (what
// awarenessProtocol.removeAwarenessStates produces) for y-protocols
// peers, and the legacy JSON {"left":true} frame for legacy peers.
func (r *Room) broadcastPresenceLeave(sub *Subscriber) {
	r.awMu.Lock()
	var gone []AwarenessEntry
	for id, e := range r.aw {
		if e.owner == sub {
			gone = append(gone, AwarenessEntry{ClientID: id, Clock: e.clock + 1, State: "null"})
			delete(r.aw, id)
		}
	}
	r.awMu.Unlock()
	if len(gone) > 0 {
		r.broadcastFiltered(EncodeAwareness(EncodeAwarenessUpdate(gone)), sub, func(s *Subscriber) bool {
			return s.aw.dialect.Load() != dialectLegacyJSON
		})
	}

	if sub.ClientID == uuid.Nil {
		return
	}
	payload, err := json.Marshal(struct {
		ClientID    string `json:"client_id"`
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Color       string `json:"color"`
		Left        bool   `json:"left"`
	}{ClientID: sub.ClientID.String(), Left: true})
	if err != nil {
		return
	}
	r.broadcastFiltered(EncodeAwareness(payload), sub, func(s *Subscriber) bool {
		return s.aw.dialect.Load() == dialectLegacyJSON
	})
}
