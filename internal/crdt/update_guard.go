package crdt

import (
	"errors"
	"fmt"
	"unicode/utf8"
)

// ErrUnsafeUpdate rejects a lib0 v1 update the server must not hand to
// yrs. yffi returns every string as a C string and calls
// `CString::new(..).unwrap()`, so a single U+0000 in the text aborts the
// whole process the next time anything reads it (Text, the FS mirror,
// SyncStep2). yrs also reads update strings with `from_utf8_unchecked`,
// so invalid UTF-8 reaches Rust as an invalid `str`. Both arrive from any
// editor socket, the REST update endpoint, federation, or a stored
// state. Found by FuzzApplyUpdate (Phase 3 quality harness).
var ErrUnsafeUpdate = errors.New("crdt: update rejected")

// checkUpdateV1 walks a lib0 v1 update exactly the way yrs decodes it
// (yrs/src/update.rs Update::decode, block.rs ItemContent::decode,
// any.rs Any::decode) and rejects it when any string holds a NUL byte or
// invalid UTF-8, or when it uses a content kind lumi never produces and
// yrs only supports behind extra features (move, weak links, subdocs).
// It is a validator only: the bytes passed to yrs are unchanged.
// Trailing bytes after the delete set are ignored, as yrs does.
func checkUpdateV1(b []byte) error {
	r := updReader{b: b}
	if err := r.update(); err != nil {
		return fmt.Errorf("%w: %v", ErrUnsafeUpdate, err)
	}
	return nil
}

type updReader struct {
	b []byte
	i int
}

var (
	errShort  = errors.New("truncated update")
	errVarint = errors.New("varint overflow")
)

func (r *updReader) u8() (byte, error) {
	if r.i >= len(r.b) {
		return 0, errShort
	}
	c := r.b[r.i]
	r.i++
	return c, nil
}

// varUint reads a lib0 unsigned varint (at most 10 bytes for 64 bits).
func (r *updReader) varUint() (uint64, error) {
	var v uint64
	for shift := uint(0); shift < 70; shift += 7 {
		c, err := r.u8()
		if err != nil {
			return 0, err
		}
		v |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, nil
		}
	}
	return 0, errVarint
}

// skipVarInt skips a lib0 signed varint (same byte framing as unsigned).
func (r *updReader) skipVarInt() error {
	for n := 0; n < 10; n++ {
		c, err := r.u8()
		if err != nil {
			return err
		}
		if c&0x80 == 0 {
			return nil
		}
	}
	return errVarint
}

func (r *updReader) skip(n uint64) error {
	if n > uint64(len(r.b)-r.i) {
		return errShort
	}
	r.i += int(n)
	return nil
}

func (r *updReader) buf() ([]byte, error) {
	n, err := r.varUint()
	if err != nil {
		return nil, err
	}
	start := r.i
	if err := r.skip(n); err != nil {
		return nil, err
	}
	return r.b[start:r.i], nil
}

func (r *updReader) str() error {
	s, err := r.buf()
	if err != nil {
		return err
	}
	if !utf8.Valid(s) {
		return errors.New("string is not valid UTF-8")
	}
	for _, c := range s {
		if c == 0 {
			return errors.New("string contains U+0000")
		}
	}
	return nil
}

// count reads a length and bounds it by the remaining bytes (every
// element takes at least one byte), so a forged length cannot make the
// walk loop for long.
func (r *updReader) count() (uint64, error) {
	n, err := r.varUint()
	if err != nil {
		return 0, err
	}
	if n > uint64(len(r.b)-r.i)+1 {
		return 0, errShort
	}
	return n, nil
}

func (r *updReader) id() error {
	if _, err := r.varUint(); err != nil { // client
		return err
	}
	_, err := r.varUint() // clock
	return err
}

const maxAnyDepth = 64

func (r *updReader) any(depth int) error {
	if depth > maxAnyDepth {
		return errors.New("any nested too deep")
	}
	tag, err := r.u8()
	if err != nil {
		return err
	}
	switch tag {
	case 127, 126, 121, 120: // undefined, null, false, true
		return nil
	case 125: // integer
		return r.skipVarInt()
	case 124: // float32
		return r.skip(4)
	case 123, 122: // float64, bigint
		return r.skip(8)
	case 119:
		return r.str()
	case 118: // map
		n, err := r.count()
		if err != nil {
			return err
		}
		for ; n > 0; n-- {
			if err := r.str(); err != nil {
				return err
			}
			if err := r.any(depth + 1); err != nil {
				return err
			}
		}
		return nil
	case 117: // array
		n, err := r.count()
		if err != nil {
			return err
		}
		for ; n > 0; n-- {
			if err := r.any(depth + 1); err != nil {
				return err
			}
		}
		return nil
	case 116: // buffer
		_, err := r.buf()
		return err
	}
	return fmt.Errorf("unknown any tag %d", tag)
}

// Block info bits and content refs (yrs/src/block.rs).
const (
	blockGC         = 0
	blockSkip       = 10
	hasOrigin       = 0x80
	hasRightOrigin  = 0x40
	hasParentSub    = 0x20
	contentDeleted  = 1
	contentJSON     = 2
	contentBinary   = 3
	contentString   = 4
	contentEmbed    = 5
	contentFormat   = 6
	contentType     = 7
	contentAny      = 8
	typeXMLElement  = 3
	typeRefsMaxSafe = 6 // array, map, text, xml element/fragment/hook/text
)

func (r *updReader) block() error {
	info, err := r.u8()
	if err != nil {
		return err
	}
	switch info {
	case blockSkip, blockGC:
		_, err := r.varUint()
		return err
	}
	if info&hasOrigin != 0 {
		if err := r.id(); err != nil {
			return err
		}
	}
	if info&hasRightOrigin != 0 {
		if err := r.id(); err != nil {
			return err
		}
	}
	if info&(hasOrigin|hasRightOrigin) == 0 {
		named, err := r.varUint()
		if err != nil {
			return err
		}
		if named == 1 {
			err = r.str()
		} else {
			err = r.id()
		}
		if err != nil {
			return err
		}
		if info&hasParentSub != 0 {
			if err := r.str(); err != nil {
				return err
			}
		}
	}
	switch info & 0x0f {
	case contentDeleted:
		_, err := r.varUint()
		return err
	case contentJSON:
		n, err := r.count()
		if err != nil {
			return err
		}
		// yrs reads len+1 strings here (`while remaining >= 0`); mirror it.
		for i := uint64(0); i <= n; i++ {
			if err := r.str(); err != nil {
				return err
			}
		}
		return nil
	case contentBinary:
		_, err := r.buf()
		return err
	case contentString, contentEmbed:
		return r.str()
	case contentFormat:
		if err := r.str(); err != nil {
			return err
		}
		return r.str()
	case contentType:
		ref, err := r.u8()
		if err != nil {
			return err
		}
		if ref > typeRefsMaxSafe {
			return fmt.Errorf("type ref %d not allowed", ref)
		}
		if ref == typeXMLElement {
			return r.str()
		}
		return nil
	case contentAny:
		n, err := r.count()
		if err != nil {
			return err
		}
		for ; n > 0; n-- {
			if err := r.any(0); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("content kind %d not allowed", info&0x0f)
}

func (r *updReader) update() error {
	clients, err := r.count()
	if err != nil {
		return err
	}
	for ; clients > 0; clients-- {
		blocks, err := r.count()
		if err != nil {
			return err
		}
		if err := r.id(); err != nil { // client, starting clock
			return err
		}
		for ; blocks > 0; blocks-- {
			if err := r.block(); err != nil {
				return err
			}
		}
	}
	// Delete set: clients × (client, ranges × (clock, len)).
	ds, err := r.count()
	if err != nil {
		return err
	}
	for ; ds > 0; ds-- {
		if _, err := r.varUint(); err != nil {
			return err
		}
		ranges, err := r.count()
		if err != nil {
			return err
		}
		for ; ranges > 0; ranges-- {
			if err := r.id(); err != nil { // clock, len: two varints
				return err
			}
		}
	}
	return nil
}
