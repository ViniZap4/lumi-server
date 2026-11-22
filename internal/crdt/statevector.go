package crdt

import (
	"errors"
	"fmt"
)

// StateVector is a decoded lib0-v1 state vector: clientID → next clock.
type StateVector map[uint64]uint64

// ErrBaseMismatch is returned when a client-supplied base (state or state
// vector) does not describe a version this server's document descends
// from, or when a base-conditioned write finds that the document moved on.
var ErrBaseMismatch = errors.New("crdt: base does not match document")

// ErrBaseUnreconstructable is returned when a client-supplied base state
// cannot be rebuilt into a document at all (undecodable, or depends on
// history it does not carry) — typically a base kept from too long ago or
// truncated. It wraps ErrBaseMismatch so existing errors.Is checks hold;
// the REST layer reports it as 409 base_too_old.
var ErrBaseUnreconstructable = fmt.Errorf("%w: base state cannot be reconstructed", ErrBaseMismatch)

// DecodeStateVector parses a lib0-v1 encoded state vector:
//
//	varUint(n) · n × (varUint(clientID) · varUint(clock))
//
// The empty input decodes to an empty vector (the state of an empty doc).
func DecodeStateVector(b []byte) (StateVector, error) {
	sv := StateVector{}
	if len(b) == 0 {
		return sv, nil
	}
	n, off, err := readVarUint(b)
	if err != nil {
		return nil, err
	}
	if n > uint64(len(b)) { // each entry needs at least 2 bytes
		return nil, fmt.Errorf("crdt: state vector entry count %d exceeds payload", n)
	}
	for i := uint64(0); i < n; i++ {
		client, k, err := readVarUint(b[off:])
		if err != nil {
			return nil, err
		}
		off += k
		clock, k, err := readVarUint(b[off:])
		if err != nil {
			return nil, err
		}
		off += k
		sv[client] = clock
	}
	if off != len(b) {
		return nil, fmt.Errorf("crdt: %d trailing bytes after state vector", len(b)-off)
	}
	return sv, nil
}

// Covers reports whether sv has seen everything other has (for every
// client, sv's clock >= other's). Zero-clock entries are ignored.
func (sv StateVector) Covers(other StateVector) bool {
	for c, clk := range other {
		if clk == 0 {
			continue
		}
		if sv[c] < clk {
			return false
		}
	}
	return true
}

// Equal reports whether both vectors describe the same set of insertions.
// Encoding order is not significant, so compare decoded maps.
func (sv StateVector) Equal(other StateVector) bool {
	return sv.Covers(other) && other.Covers(sv)
}

func readVarUint(buf []byte) (uint64, int, error) {
	var v uint64
	var shift uint
	for i := 0; i < len(buf); i++ {
		if shift >= 64 {
			return 0, 0, errors.New("crdt: varint overflow")
		}
		b := buf[i]
		v |= uint64(b&0x7f) << shift
		if b&0x80 == 0 {
			return v, i + 1, nil
		}
		shift += 7
	}
	return 0, 0, errors.New("crdt: truncated varint")
}
