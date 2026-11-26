package crdt

/*
#include <stdlib.h>
#include "libyrs.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
	"unsafe"
)

// Edit is one ranged change to the note text: delete Del UTF-16 code
// units at Pos, then insert Ins there. Pos and Del are offsets into the
// text as it stood BEFORE any edit of the same batch (Yjs / JavaScript
// string semantics, the unit yrs is configured with in NewDoc).
//
// A batch is valid when its edits are in ascending Pos order and
// disjoint (edit[i].Pos+edit[i].Del <= edit[i+1].Pos), every boundary
// lies inside the text and on a code-point boundary (never between the
// two halves of a surrogate pair), and every Ins is valid UTF-8 without
// NUL bytes. Several pure inserts at the same Pos land in batch order.
type Edit struct {
	Pos int
	Del int
	Ins string
}

// ErrInvalidEdits is returned (wrapped, with the reason) when a batch of
// edits violates the contract documented on Edit. Nothing is applied.
var ErrInvalidEdits = errors.New("crdt: invalid edits")

// Planner computes the edits for a planned change from the current text.
// It runs while the document lock is held and so must not call any
// method of the Doc. Returning no edits (or only empty ones) is a no-op.
type Planner func(text string) ([]Edit, error)

// ApplyEdits applies a batch of ranged edits (see Edit) in a single yrs
// transaction and returns the lib0-v1 update describing exactly this
// change (empty when every edit is empty). origin is the yrs transaction
// origin label. An invalid batch returns an error wrapping
// ErrInvalidEdits and leaves the document untouched.
func (d *Doc) ApplyEdits(edits []Edit, origin string) ([]byte, error) {
	return d.ApplyPlanned(func(string) ([]Edit, error) { return edits, nil }, origin)
}

// ApplyPlanned reads the current text, asks plan for the edits against
// it and applies them, all under the document lock so no other writer
// can interleave between the read and the write. Validation and the
// returned update follow ApplyEdits. An error from plan is returned
// unchanged and nothing is applied.
func (d *Doc) ApplyPlanned(plan Planner, origin string) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, errClosed
	}
	current := readUnderReadTxn(d.ptr, d.contentB)
	edits, err := plan(current)
	if err != nil {
		return nil, err
	}
	edits, err = normaliseEdits(current, edits)
	if err != nil {
		return nil, err
	}
	if len(edits) == 0 {
		return []byte{}, nil
	}

	svBefore := stateVectorUnderReadTxn(d.ptr)
	var originPtr *C.char
	var originLen C.uint32_t
	if origin != "" {
		originPtr = C.CString(origin)
		defer C.free(unsafe.Pointer(originPtr))
		originLen = C.uint32_t(len(origin))
	}
	txn := C.ydoc_write_transaction(d.ptr, originLen, originPtr)
	if txn == nil {
		return nil, errors.New("crdt: write transaction unavailable")
	}
	// Right to left: offsets of earlier edits stay valid, and inserts
	// sharing one Pos end up in batch order.
	branch := d.contentB
	for i := len(edits) - 1; i >= 0; i-- {
		e := edits[i]
		if e.Del > 0 {
			C.ytext_remove_range(branch, txn, C.uint32_t(e.Pos), C.uint32_t(e.Del))
		}
		if e.Ins != "" {
			cval := C.CString(e.Ins)
			C.ytext_insert(branch, txn, C.uint32_t(e.Pos), cval, nil)
			C.free(unsafe.Pointer(cval))
		}
	}
	var n C.uint32_t
	var svPtr *C.char
	var svLen C.uint32_t
	if len(svBefore) > 0 {
		svPtr = (*C.char)(unsafe.Pointer(&svBefore[0]))
		svLen = C.uint32_t(len(svBefore))
	}
	updatePtr := C.ytransaction_state_diff_v1(txn, svPtr, svLen, &n)
	C.ytransaction_commit(txn)
	if updatePtr == nil {
		return []byte{}, nil
	}
	defer C.ybinary_destroy(updatePtr, n)
	return C.GoBytes(unsafe.Pointer(updatePtr), C.int(n)), nil
}

// normaliseEdits validates edits against text (UTF-16 offsets) and drops
// empty ones (an empty edit must still be in range and on a boundary).
// It walks text once: O(len(text)+len(edits)).
func normaliseEdits(text string, edits []Edit) ([]Edit, error) {
	if len(edits) == 0 {
		return nil, nil
	}
	prevEnd := 0
	bounds := make([]int, 0, 2*len(edits)) // ascending: every Pos and Pos+Del
	out := make([]Edit, 0, len(edits))
	for i, e := range edits {
		if e.Pos < 0 || e.Del < 0 {
			return nil, fmt.Errorf("%w: edit %d has a negative offset", ErrInvalidEdits, i)
		}
		if e.Pos < prevEnd {
			return nil, fmt.Errorf("%w: edit %d overlaps or is out of order", ErrInvalidEdits, i)
		}
		if !utf8.ValidString(e.Ins) {
			return nil, fmt.Errorf("%w: edit %d inserts invalid UTF-8", ErrInvalidEdits, i)
		}
		if strings.IndexByte(e.Ins, 0) >= 0 {
			return nil, fmt.Errorf("%w: edit %d inserts a NUL byte", ErrInvalidEdits, i)
		}
		prevEnd = e.Pos + e.Del
		bounds = append(bounds, e.Pos, prevEnd)
		if e.Del > 0 || e.Ins != "" {
			out = append(out, e)
		}
	}
	// unit is the UTF-16 offset of the rune starting at the current byte;
	// a boundary is legal when it equals a rune start or the text length.
	bi, unit := 0, 0
	for _, r := range text {
		for bi < len(bounds) && bounds[bi] <= unit {
			if bounds[bi] < unit {
				return nil, fmt.Errorf("%w: offset %d splits a surrogate pair", ErrInvalidEdits, bounds[bi])
			}
			bi++
		}
		if bi == len(bounds) {
			return out, nil
		}
		if r > 0xFFFF {
			unit += 2
		} else {
			unit++
		}
	}
	for ; bi < len(bounds); bi++ {
		switch {
		case bounds[bi] < unit:
			return nil, fmt.Errorf("%w: offset %d splits a surrogate pair", ErrInvalidEdits, bounds[bi])
		case bounds[bi] > unit:
			return nil, fmt.Errorf("%w: offset %d is past the end of the text (%d units)", ErrInvalidEdits, bounds[bi], unit)
		}
	}
	return out, nil
}

// ByteEditsToUTF16 converts edits whose Pos/Del are UTF-8 byte offsets
// into text (what Go planners naturally compute) into UTF-16 code-unit
// edits for ApplyEdits. Edits must be ascending and disjoint and every
// offset must fall on a rune boundary inside text.
func ByteEditsToUTF16(text string, edits []Edit) ([]Edit, error) {
	out := make([]Edit, len(edits))
	byteOff, unit := 0, 0
	advance := func(to int) error {
		if to < byteOff || to > len(text) {
			return fmt.Errorf("%w: byte offset %d out of order or past the end", ErrInvalidEdits, to)
		}
		if to < len(text) && !utf8.RuneStart(text[to]) {
			return fmt.Errorf("%w: byte offset %d is inside a code point", ErrInvalidEdits, to)
		}
		unit += utf16Len(text[byteOff:to])
		byteOff = to
		return nil
	}
	for i, e := range edits {
		if e.Pos < 0 || e.Del < 0 {
			return nil, fmt.Errorf("%w: edit %d has a negative offset", ErrInvalidEdits, i)
		}
		if err := advance(e.Pos); err != nil {
			return nil, err
		}
		start := unit
		if err := advance(e.Pos + e.Del); err != nil {
			return nil, err
		}
		out[i] = Edit{Pos: start, Del: unit - start, Ins: e.Ins}
	}
	return out, nil
}
