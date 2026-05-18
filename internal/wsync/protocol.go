// Package wsync implements the Yjs WebSocket live-sync layer for lumi
// v2 Phase 2.3. It speaks the standard y-protocols v1 wire format over
// a Fiber WebSocket upgrade. Each note has at most one in-memory
// *crdt.Doc shared by all subscribers; inbound updates are persisted
// via the CRDT registry and fanned out to other subscribers.
//
// Wire format (https://github.com/yjs/y-protocols/blob/master/PROTOCOL.md):
//
//	Message     ::= varInt(messageType) + payload
//	messageType ::= 0 Sync | 1 Awareness | 3 Auth | 4 QueryAwareness
//
//	Sync payload ::= varInt(syncSubType) + body
//	syncSubType  ::= 0 Step1 (body=stateVector)
//	                | 1 Step2 (body=update)
//	                | 2 Update (body=update)
//
//	Awareness payload ::= varBytes(awarenessUpdate)
//
// varInt is lib0's unsigned LEB128. varBytes is varInt(len) + bytes.
package wsync

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Message types (top-level).
const (
	MessageSync            byte = 0
	MessageAwareness       byte = 1
	MessageAuth            byte = 3
	MessageQueryAwareness  byte = 4
)

// Sync sub-types.
const (
	SyncStep1  byte = 0
	SyncStep2  byte = 1
	SyncUpdate byte = 2
)

// ErrShortRead indicates the caller passed a truncated message buffer.
var ErrShortRead = errors.New("wsync: short read")

// readVarUint reads a lib0 unsigned LEB128 varint from r. Returns the
// value and how many bytes it consumed.
func readVarUint(buf []byte) (uint64, int, error) {
	var v uint64
	var shift uint
	for i := 0; i < len(buf); i++ {
		b := buf[i]
		if shift >= 64 {
			return 0, 0, fmt.Errorf("wsync: varint overflow")
		}
		v |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return v, i + 1, nil
		}
		shift += 7
	}
	return 0, 0, ErrShortRead
}

// writeVarUint appends a lib0 unsigned LEB128 varint to dst.
func writeVarUint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

// readVarBytes reads varint(length) + bytes from buf, returning the
// payload and bytes consumed.
func readVarBytes(buf []byte) ([]byte, int, error) {
	n, off, err := readVarUint(buf)
	if err != nil {
		return nil, 0, err
	}
	end := off + int(n)
	if end > len(buf) {
		return nil, 0, ErrShortRead
	}
	out := make([]byte, n)
	copy(out, buf[off:end])
	return out, end, nil
}

// writeVarBytes appends varint(len(b)) + b to dst.
func writeVarBytes(dst, b []byte) []byte {
	dst = writeVarUint(dst, uint64(len(b)))
	return append(dst, b...)
}

// ---- High-level message helpers --------------------------------------------

// EncodeSyncStep1 produces a `[0 (Sync), 0 (Step1), sv]` message
// carrying the local state vector. Server sends this on connect (so
// the client knows what to send next) — clients also send it on open.
func EncodeSyncStep1(sv []byte) []byte {
	out := make([]byte, 0, 4+len(sv))
	out = append(out, MessageSync, SyncStep1)
	return writeVarBytes(out, sv)
}

// EncodeSyncStep2 produces a `[0 (Sync), 1 (Step2), update]` message.
// Response to SyncStep1: server computes the state-diff against the
// peer's state vector and ships it.
func EncodeSyncStep2(update []byte) []byte {
	out := make([]byte, 0, 4+len(update))
	out = append(out, MessageSync, SyncStep2)
	return writeVarBytes(out, update)
}

// EncodeSyncUpdate produces a `[0 (Sync), 2 (Update), update]` message
// for fan-out broadcasts of an applied update.
func EncodeSyncUpdate(update []byte) []byte {
	out := make([]byte, 0, 4+len(update))
	out = append(out, MessageSync, SyncUpdate)
	return writeVarBytes(out, update)
}

// EncodeAwareness produces a `[1 (Awareness), update]` message.
// Awareness updates are opaque to lumi-server; we relay them.
func EncodeAwareness(update []byte) []byte {
	out := make([]byte, 0, 4+len(update))
	out = append(out, MessageAwareness)
	return writeVarBytes(out, update)
}

// ParsedMessage is the decoded form of an inbound frame.
type ParsedMessage struct {
	Type    byte
	SyncSub byte // valid only when Type == MessageSync
	Body    []byte
}

// DecodeMessage parses a single binary WebSocket frame. Returns
// ErrShortRead if the frame is truncated mid-varint.
func DecodeMessage(buf []byte) (ParsedMessage, error) {
	if len(buf) == 0 {
		return ParsedMessage{}, ErrShortRead
	}
	m := ParsedMessage{Type: buf[0]}
	rest := buf[1:]

	switch m.Type {
	case MessageSync:
		if len(rest) == 0 {
			return m, ErrShortRead
		}
		m.SyncSub = rest[0]
		rest = rest[1:]
		body, _, err := readVarBytes(rest)
		if err != nil {
			return m, err
		}
		m.Body = body
		return m, nil

	case MessageAwareness:
		body, _, err := readVarBytes(rest)
		if err != nil {
			return m, err
		}
		m.Body = body
		return m, nil

	case MessageQueryAwareness:
		// No body. We do not maintain a server-side awareness register
		// in slice 2.3 — reply is just an empty awareness fan-out.
		return m, nil

	case MessageAuth:
		// Auth message bodies vary by Yjs client; we don't enforce.
		return m, nil

	default:
		return m, fmt.Errorf("wsync: unknown message type %d", m.Type)
	}
}

// ---- diagnostic helpers ----------------------------------------------------

// FormatMessage returns a short human-readable label, useful for logs.
// Not on the hot path.
func FormatMessage(m ParsedMessage) string {
	switch m.Type {
	case MessageSync:
		switch m.SyncSub {
		case SyncStep1:
			return fmt.Sprintf("sync.step1(sv=%dB)", len(m.Body))
		case SyncStep2:
			return fmt.Sprintf("sync.step2(update=%dB)", len(m.Body))
		case SyncUpdate:
			return fmt.Sprintf("sync.update(%dB)", len(m.Body))
		default:
			return fmt.Sprintf("sync.unknown(sub=%d)", m.SyncSub)
		}
	case MessageAwareness:
		return fmt.Sprintf("awareness(%dB)", len(m.Body))
	case MessageQueryAwareness:
		return "query-awareness"
	case MessageAuth:
		return "auth"
	default:
		return fmt.Sprintf("unknown(type=%d)", m.Type)
	}
}

// silence unused-import nag in case BinaryEndian changes later.
var _ = binary.LittleEndian
var _ = io.EOF
