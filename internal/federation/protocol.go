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
//	noteAnnounce:= noteMeta [varBytes(epoch)]     — peer may lack this note;
//	                                                create metadata before sync
//
// CRDT epochs (docs/CRDT-CLIENT-PROTOCOL.md §12) ride as OPTIONAL trailing
// data so peers predating them (whose decoders ignore trailing bytes)
// keep working: a manifest may end with varUint(n) n×varBytes(epoch),
// positional with its entries ("" = unknown), and an announce with one
// varBytes(epoch). A receiver creating the note's row adopts the epoch:
// the doc it then receives over the relay IS that history.
const (
	frameManifest     uint64 = 1
	frameNoteSync     uint64 = 2
	frameNoteAnnounce uint64 = 3
	frameNoteDelete   uint64 = 4 // varBytes(id) — note removed at the peer
	frameControlState uint64 = 5 // varBytes(stateJSON) varBytes(sig) — home → follower
	frameControlAck   uint64 = 6 // varUint(seq) — follower → home
	frameNoteMove     uint64 = 7 // noteMeta — note renamed/moved at the peer

	// Relay protocol v2 (docs/SPEC-ESPELHO-SELADO.md §A4.2). Only sent to a
	// peer that advertised v2 (see RelayProtoVersion), so v1 peers never
	// see them.
	frameMirrorAck  uint64 = 8  // varUint(home_vault_seq)            mirror → home
	frameResumeFrom uint64 = 9  // varUint(home_vault_seq)            mirror → home (reserved, M2)
	frameChangesEnd uint64 = 10 // varUint(home_vault_seq)            home → mirror
	frameNoteMeta2  uint64 = 11 // noteMeta varBytes(frontmatterJSON) — frontmatter (G1)
)

// RelayProtoVersion is the relay protocol this server speaks. v2 adds the
// frames 8–11 and the mirror mode. A follower advertises it with the
// "proto" query parameter of the relay WebSocket; home advertises it as
// trailing data of the manifest (v1 decoders ignore both). A side sends
// v2 frames only to a peer that advertised v2.
const RelayProtoVersion = 2

// maxFrontmatterBytes caps the frontmatter JSON of one noteMeta2 frame.
const maxFrontmatterBytes = 16 << 10

// syncAuthMessagePrefix versions the signed WS-upgrade auth (v3 F2). The
// follower signs prefix|nonce|vault_id|follower_url with its enrolled key.
const syncAuthMessagePrefix = "lumi-federation-sync-v1"

// SyncAuthMessage is the canonical byte string signed for relay upgrades.
func SyncAuthMessage(nonce, vaultID, followerURL string) []byte {
	return []byte(syncAuthMessagePrefix + "|" + nonce + "|" + vaultID + "|" + followerURL)
}

var errFrameTruncated = errors.New("federation: truncated frame")

// Relay resource caps. A federated peer is authenticated but not trusted
// with our memory: every WebSocket read and every decoded frame is bounded.
const (
	// maxRelayMessageBytes caps a single WS message (both sides call
	// SetReadLimit with it) and therefore any frame. Generous enough for a
	// full y-doc state of a note at the 4 MiB REST body limit plus history,
	// or a manifest of maxManifestEntries typical notes.
	maxRelayMessageBytes = 32 << 20
	// maxManifestEntries bounds how many notes one manifest may list.
	maxManifestEntries = 200_000
	// Per-field caps on note metadata (ids are <= 80 bytes server-side).
	maxNoteIDBytes    = 256
	maxNotePathBytes  = 4096
	maxNoteTitleBytes = 4096
	maxNoteEpochBytes = 64
	// minNoteMetaBytes is the smallest encoded NoteMeta (three empty
	// varBytes); used to bound manifest pre-allocation by the input size.
	minNoteMetaBytes = 3
)

var errFrameTooLarge = errors.New("federation: frame exceeds size limit")

// NoteMeta identifies a note across the link. Path/title are creation
// metadata for peers that don't have the note yet.
type NoteMeta struct {
	ID    string
	Path  string
	Title string
	// Epoch is the sender's crdt_epoch for the note ("" when unknown or
	// sent by a peer predating epochs). Optional on the wire.
	Epoch string
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
	if len(id) > maxNoteIDBytes || len(path) > maxNotePathBytes || len(title) > maxNoteTitleBytes {
		return NoteMeta{}, 0, fmt.Errorf("%w: note metadata field too long", errFrameTooLarge)
	}
	return NoteMeta{ID: id, Path: path, Title: title}, n1 + n2 + n3, nil
}

// EncodeManifest lists every note the sender has for the vault, followed
// by the optional trailing epoch list and, after it, the sender's relay
// protocol version (v1 decoders stop reading after the epochs).
func EncodeManifest(notes []NoteMeta) []byte {
	out := writeVarUint(nil, frameManifest)
	out = writeVarUint(out, uint64(len(notes)))
	for _, m := range notes {
		out = appendNoteMeta(out, m)
	}
	out = writeVarUint(out, uint64(len(notes)))
	for _, m := range notes {
		out = writeVarBytes(out, []byte(m.Epoch))
	}
	return writeVarUint(out, RelayProtoVersion)
}

// EncodeNoteMeta2 carries a note's frontmatter (the keys not derived from
// the CRDT or the row: tags, created_at, unknown keys) as a JSON object.
func EncodeNoteMeta2(m NoteMeta, frontmatterJSON []byte) []byte {
	out := writeVarUint(nil, frameNoteMeta2)
	out = appendNoteMeta(out, m)
	return writeVarBytes(out, frontmatterJSON)
}

// EncodeSeqFrame builds the seq-only frames (mirror ack, resume, changes end).
func encodeSeqFrame(typ uint64, seq int64) []byte {
	if seq < 0 {
		seq = 0
	}
	return writeVarUint(writeVarUint(nil, typ), uint64(seq))
}

// EncodeMirrorAck reports the highest home vault seq the mirror applied.
func EncodeMirrorAck(seq int64) []byte { return encodeSeqFrame(frameMirrorAck, seq) }

// EncodeChangesEnd tells the mirror home's vault seq after everything sent
// before it.
func EncodeChangesEnd(seq int64) []byte { return encodeSeqFrame(frameChangesEnd, seq) }

func readEpoch(buf []byte) (string, int, error) {
	e, n, err := readVarString(buf)
	if err != nil {
		return "", 0, err
	}
	if len(e) > maxNoteEpochBytes {
		return "", 0, fmt.Errorf("%w: note epoch too long", errFrameTooLarge)
	}
	return e, n, nil
}

// EncodeNoteSync wraps a per-note y-protocols sync payload.
func EncodeNoteSync(noteID string, payload []byte) []byte {
	out := writeVarUint(nil, frameNoteSync)
	out = writeVarBytes(out, []byte(noteID))
	return writeVarBytes(out, payload)
}

// EncodeNoteAnnounce advertises a note the peer may not have yet, with
// its epoch as optional trailing data.
func EncodeNoteAnnounce(m NoteMeta) []byte {
	out := writeVarUint(nil, frameNoteAnnounce)
	out = appendNoteMeta(out, m)
	if m.Epoch != "" {
		out = writeVarBytes(out, []byte(m.Epoch))
	}
	return out
}

// EncodeNoteDelete propagates a note deletion.
func EncodeNoteDelete(noteID string) []byte {
	out := writeVarUint(nil, frameNoteDelete)
	return writeVarBytes(out, []byte(noteID))
}

// EncodeNoteMove propagates a rename/move (new path/title for an id).
func EncodeNoteMove(m NoteMeta) []byte {
	out := writeVarUint(nil, frameNoteMove)
	return appendNoteMeta(out, m)
}

// EncodeControlState carries home's signed control document.
func EncodeControlState(stateJSON, sig []byte) []byte {
	out := writeVarUint(nil, frameControlState)
	out = writeVarBytes(out, stateJSON)
	return writeVarBytes(out, sig)
}

// EncodeControlAck reports the follower's applied control-state cursor.
func EncodeControlAck(seq int64) []byte {
	out := writeVarUint(nil, frameControlAck)
	return writeVarUint(out, uint64(seq))
}

// ---- frame decode ---------------------------------------------------------------

// Frame is one decoded relay frame; exactly one of the payload fields is
// meaningful depending on Type.
type Frame struct {
	Type     uint64
	Manifest []NoteMeta // frameManifest
	Note     NoteMeta   // frameNoteAnnounce
	NoteID   string     // frameNoteSync / frameNoteDelete
	Payload  []byte     // frameNoteSync: y-protocols message; frameControlState: state JSON
	Sig      []byte     // frameControlState
	Seq      int64      // frameControlAck, frameMirrorAck, frameResumeFrom, frameChangesEnd
	// Proto is the peer's relay protocol version advertised in a
	// manifest (1 when absent).
	Proto int
}

func DecodeFrame(buf []byte) (Frame, error) {
	if len(buf) > maxRelayMessageBytes {
		return Frame{}, errFrameTooLarge
	}
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
		if count > maxManifestEntries {
			return Frame{}, fmt.Errorf("%w: manifest lists %d notes (max %d)", errFrameTooLarge, count, maxManifestEntries)
		}
		// Each entry needs at least minNoteMetaBytes, so a count the body
		// cannot possibly hold is a lie: reject before allocating.
		if count > uint64(len(body)/minNoteMetaBytes) {
			return Frame{}, errFrameTruncated
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
		if len(body) > 0 {
			// Optional epoch list (peers predating epochs omit it).
			ecount, n, err := readVarUint(body)
			if err != nil {
				return Frame{}, err
			}
			if ecount != count {
				return Frame{}, fmt.Errorf("federation: manifest lists %d epochs for %d notes", ecount, count)
			}
			body = body[n:]
			for i := range notes {
				e, n, err := readEpoch(body)
				if err != nil {
					return Frame{}, err
				}
				notes[i].Epoch = e
				body = body[n:]
			}
		}
		proto := 1
		if len(body) > 0 {
			if v, _, err := readVarUint(body); err == nil && v > 0 && v < 1<<16 {
				proto = int(v)
			}
		}
		return Frame{Type: typ, Manifest: notes, Proto: proto}, nil
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
	case frameNoteAnnounce, frameNoteMove:
		m, n, err := readNoteMeta(body)
		if err != nil {
			return Frame{}, err
		}
		if typ == frameNoteAnnounce && len(body) > n {
			if m.Epoch, _, err = readEpoch(body[n:]); err != nil {
				return Frame{}, err
			}
		}
		return Frame{Type: typ, Note: m}, nil
	case frameNoteDelete:
		noteID, _, err := readVarString(body)
		if err != nil {
			return Frame{}, err
		}
		return Frame{Type: typ, NoteID: noteID}, nil
	case frameControlState:
		state, n, err := readVarBytes(body)
		if err != nil {
			return Frame{}, err
		}
		sig, _, err := readVarBytes(body[n:])
		if err != nil {
			return Frame{}, err
		}
		return Frame{Type: typ, Payload: state, Sig: sig}, nil
	case frameControlAck, frameMirrorAck, frameResumeFrom, frameChangesEnd:
		seq, _, err := readVarUint(body)
		if err != nil {
			return Frame{}, err
		}
		if seq > 1<<62 {
			return Frame{}, fmt.Errorf("federation: seq out of range")
		}
		return Frame{Type: typ, Seq: int64(seq)}, nil
	case frameNoteMeta2:
		m, n, err := readNoteMeta(body)
		if err != nil {
			return Frame{}, err
		}
		fm, _, err := readVarBytes(body[n:])
		if err != nil {
			return Frame{}, err
		}
		if len(fm) > maxFrontmatterBytes {
			return Frame{}, fmt.Errorf("%w: frontmatter larger than %d bytes", errFrameTooLarge, maxFrontmatterBytes)
		}
		return Frame{Type: typ, Note: m, Payload: fm}, nil
	default:
		// Forward compatibility: a frame type from a newer peer is
		// skipped, never a reason to drop the link.
		return Frame{Type: typ}, nil
	}
}
