package federation

import (
	"errors"
	"fmt"
)

// F2 relay frames. One WebSocket per (vault, peer link); frames multiplex
// per-note y-protocols sync messages plus vault-level metadata. Encoding is
// lib0-style varints for symmetry with the client sync protocol (wsync).
//
//	frame       := varUint(frameType) body
//	manifest    := varUint(n) n×noteMeta          — home → follower on connect
//	noteMeta    := varBytes(id) varBytes(path) varBytes(title)
//	noteSync    := varBytes(id) varBytes(payload) — payload is a y-protocols
//	                                                sync message (Step1/2/Update)
//	noteAnnounce:= noteMeta                       — peer may lack this note;
//	                                                create metadata before sync
const (
	frameManifest     uint64 = 1
	frameNoteSync     uint64 = 2
	frameNoteAnnounce uint64 = 3
)

// syncAuthMessagePrefix versions the signed WS-upgrade auth (v3 F2). The
// follower signs prefix|nonce|vault_id|follower_url with its enrolled key.
const syncAuthMessagePrefix = "lumi-federation-sync-v1"

// SyncAuthMessage is the canonical byte string signed for relay upgrades.
func SyncAuthMessage(nonce, vaultID, followerURL string) []byte {
	return []byte(syncAuthMessagePrefix + "|" + nonce + "|" + vaultID + "|" + followerURL)
}

var errFrameTruncated = errors.New("federation: truncated frame")

// NoteMeta identifies a note across the link. Path/title are creation
// metadata for peers that don't have the note yet.
type NoteMeta struct {
	ID    string
	Path  string
	Title string
}

// ---- lib0 varint helpers (mirrors wsync's unexported codec) --------------------

func writeVarUint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

func readVarUint(buf []byte) (uint64, int, error) {
	var v uint64
	var shift uint
	for i := 0; i < len(buf); i++ {
		b := buf[i]
		v |= uint64(b&0x7f) << shift
		if b < 0x80 {
			return v, i + 1, nil
		}
		shift += 7
		if shift > 63 {
			return 0, 0, fmt.Errorf("federation: varint overflow")
		}
	}
	return 0, 0, errFrameTruncated
}

func writeVarBytes(dst, b []byte) []byte {
	dst = writeVarUint(dst, uint64(len(b)))
	return append(dst, b...)
}

func readVarBytes(buf []byte) ([]byte, int, error) {
	n, consumed, err := readVarUint(buf)
	if err != nil {
		return nil, 0, err
	}
	rest := buf[consumed:]
	if uint64(len(rest)) < n {
		return nil, 0, errFrameTruncated
	}
	return rest[:n], consumed + int(n), nil
}

func readVarString(buf []byte) (string, int, error) {
	b, n, err := readVarBytes(buf)
	return string(b), n, err
}

// ---- frame encode ---------------------------------------------------------------

func appendNoteMeta(dst []byte, m NoteMeta) []byte {
	dst = writeVarBytes(dst, []byte(m.ID))
	dst = writeVarBytes(dst, []byte(m.Path))
	return writeVarBytes(dst, []byte(m.Title))
}

func readNoteMeta(buf []byte) (NoteMeta, int, error) {
	id, n1, err := readVarString(buf)
	if err != nil {
		return NoteMeta{}, 0, err
	}
	path, n2, err := readVarString(buf[n1:])
	if err != nil {
		return NoteMeta{}, 0, err
	}
	title, n3, err := readVarString(buf[n1+n2:])
	if err != nil {
		return NoteMeta{}, 0, err
	}
	return NoteMeta{ID: id, Path: path, Title: title}, n1 + n2 + n3, nil
}

// EncodeManifest lists every note the sender has for the vault.
func EncodeManifest(notes []NoteMeta) []byte {
	out := writeVarUint(nil, frameManifest)
	out = writeVarUint(out, uint64(len(notes)))
	for _, m := range notes {
		out = appendNoteMeta(out, m)
	}
	return out
}

// EncodeNoteSync wraps a per-note y-protocols sync payload.
func EncodeNoteSync(noteID string, payload []byte) []byte {
	out := writeVarUint(nil, frameNoteSync)
	out = writeVarBytes(out, []byte(noteID))
	return writeVarBytes(out, payload)
}

// EncodeNoteAnnounce advertises a note the peer may not have yet.
func EncodeNoteAnnounce(m NoteMeta) []byte {
	out := writeVarUint(nil, frameNoteAnnounce)
	return appendNoteMeta(out, m)
}

// ---- frame decode ---------------------------------------------------------------

// Frame is one decoded relay frame; exactly one of the payload fields is
// meaningful depending on Type.
type Frame struct {
	Type     uint64
	Manifest []NoteMeta // frameManifest
	Note     NoteMeta   // frameNoteAnnounce
	NoteID   string     // frameNoteSync
	Payload  []byte     // frameNoteSync: y-protocols sync message
}

func DecodeFrame(buf []byte) (Frame, error) {
	typ, n, err := readVarUint(buf)
	if err != nil {
		return Frame{}, err
	}
	body := buf[n:]
	switch typ {
	case frameManifest:
		count, n, err := readVarUint(body)
		if err != nil {
			return Frame{}, err
		}
		body = body[n:]
		if count > 1_000_000 {
			return Frame{}, fmt.Errorf("federation: absurd manifest size %d", count)
		}
		notes := make([]NoteMeta, 0, count)
		for i := uint64(0); i < count; i++ {
			m, n, err := readNoteMeta(body)
			if err != nil {
				return Frame{}, err
			}
			notes = append(notes, m)
			body = body[n:]
		}
		return Frame{Type: typ, Manifest: notes}, nil
	case frameNoteSync:
		noteID, n, err := readVarString(body)
		if err != nil {
			return Frame{}, err
		}
		payload, _, err := readVarBytes(body[n:])
		if err != nil {
			return Frame{}, err
		}
		return Frame{Type: typ, NoteID: noteID, Payload: payload}, nil
	case frameNoteAnnounce:
		m, _, err := readNoteMeta(body)
		if err != nil {
			return Frame{}, err
		}
		return Frame{Type: typ, Note: m}, nil
	default:
		return Frame{}, fmt.Errorf("federation: unknown frame type %d", typ)
	}
}
