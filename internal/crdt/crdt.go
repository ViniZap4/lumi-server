// Package crdt is a narrow cgo wrapper around the yffi C API of the yrs
// CRDT engine. We expose only the operations needed by lumi-server v2
// Phase 2.2 — load a document from a persisted state, read its text root,
// apply a textual diff, encode state vectors and update blobs.
//
// # Threading
//
// yrs serialises transactions per-document via an internal RwLock and
// returns NULL from ydoc_read_transaction / ydoc_write_transaction if a
// transaction is already open. We never want a goroutine to receive a
// surprise NULL pointer, so every Doc holds its own sync.Mutex and all
// public methods take it. Callers may freely share a *Doc across
// goroutines; the wrapper serialises them.
//
// # Memory
//
// Heap pointers returned by yffi (char* strings, char* binaries) are
// released via ystring_destroy / ybinary_destroy as soon as we have
// copied the contents into Go memory. Doc itself is released by
// ydoc_destroy on Close; a runtime.SetFinalizer guards against leaks
// when a caller forgets to Close.
//
// # Text encoding
//
// yrs Text uses UTF-16 code-unit offsets for index/length arguments,
// matching Yjs/JavaScript string semantics. The wrapper translates from
// Go UTF-8 strings to UTF-16 offsets transparently in ApplyTextDiff.
package crdt

/*
#cgo CFLAGS: -I${SRCDIR}/include
#cgo LDFLAGS: -L${SRCDIR}/lib -lyrs
#cgo darwin LDFLAGS: -framework Foundation -framework Security -framework SystemConfiguration
#cgo linux LDFLAGS: -lm -ldl -lpthread

#include <stdlib.h>
#include <string.h>
#include "libyrs.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"unicode/utf16"
	"unsafe"
)

// rootBranchName is the YText root the entire note body lives in.
// Persisted updates reference this key; do not change without a
// migration path.
const rootBranchName = "content"

// Doc is the Go-side handle for a yrs YDoc. Safe for concurrent use.
//
// The "content" YText root is created eagerly at construction time and
// its Branch pointer is cached. Calling yrs's `ytext()` lazily inside
// a read transaction would deadlock: the function takes an internal
// write lock to allocate the root, and our read transaction holds the
// same RwLock in shared mode. By materialising the root once up-front
// inside a dedicated write transaction we side-step the deadlock and
// gain a fast Branch handle for subsequent text ops.
type Doc struct {
	mu       sync.Mutex
	ptr      *C.YDoc
	contentB *C.Branch
	closed   bool
}

// NewDoc allocates a fresh, empty CRDT document. The caller owns the
// returned Doc and must Close it when done; SetFinalizer covers leaks.
//
// The "content" YText root is materialised via ytext() called OUTSIDE
// any transaction. Internally yrs grabs the doc's exclusive lock to
// allocate the root; calling it inside our own write transaction
// deadlocks against the same lock (parking_lot RwLock is not
// re-entrant). Calling it on the bare doc lets yrs serialise the root
// allocation through its own internal txn, which is fine — we just
// can't hold our own.
func NewDoc() *Doc {
	d := &Doc{ptr: C.ydoc_new()}
	if d.ptr == nil {
		panic("crdt: ydoc_new returned NULL")
	}
	cname := C.CString(rootBranchName)
	defer C.free(unsafe.Pointer(cname))
	d.contentB = C.ytext(d.ptr, cname)
	if d.contentB == nil {
		C.ydoc_destroy(d.ptr)
		panic("crdt: ytext returned NULL while seeding root")
	}
	runtime.SetFinalizer(d, (*Doc).finalize)
	return d
}

// LoadDoc allocates a fresh document and applies the given persisted
// state (a lib0 v1 update blob, e.g. the union of a snapshot and the
// replayed update log) before returning. The caller owns the result and
// must Close it.
func LoadDoc(state []byte) (*Doc, error) {
	d := NewDoc()
	if len(state) == 0 {
		return d, nil
	}
	if err := d.ApplyUpdate(state); err != nil {
		_ = d.Close()
		return nil, err
	}
	return d, nil
}

// Close releases the underlying YDoc. Idempotent.
func (d *Doc) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	C.ydoc_destroy(d.ptr)
	d.ptr = nil
	d.contentB = nil
	d.closed = true
	runtime.SetFinalizer(d, nil)
	return nil
}

func (d *Doc) finalize() {
	// Synchronisation is irrelevant inside a finalizer — the GC has
	// already established no other reference exists — but we keep the
	// lock as defence in depth.
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	C.ydoc_destroy(d.ptr)
	d.ptr = nil
	d.contentB = nil
	d.closed = true
}

// errClosed is returned for operations on a closed Doc.
var errClosed = errors.New("crdt: document is closed")

// ---- Text reads ------------------------------------------------------------

// Text returns the current value of the content root as a UTF-8 string.
func (d *Doc) Text() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return "", errClosed
	}
	txn := C.ydoc_read_transaction(d.ptr)
	if txn == nil {
		return "", errors.New("crdt: read transaction unavailable")
	}
	defer C.ytransaction_commit(txn)
	return readContent(d.contentB, txn), nil
}

// readContent assumes the caller holds an open transaction and uses the
// pre-materialised content Branch from the Doc.
func readContent(branch *C.Branch, txn *C.YTransaction) string {
	if branch == nil {
		return ""
	}
	raw := C.ytext_string(branch, txn)
	if raw == nil {
		return ""
	}
	defer C.ystring_destroy(raw)
	return C.GoString(raw)
}

// ---- State vectors + updates -----------------------------------------------

// StateVectorV1 returns the lib0-v1-encoded state vector of the current
// document. The blob is opaque to clients and only meaningful as a
// "what does this peer already have?" identifier.
func (d *Doc) StateVectorV1() ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, errClosed
	}
	txn := C.ydoc_read_transaction(d.ptr)
	if txn == nil {
		return nil, errors.New("crdt: read transaction unavailable")
	}
	defer C.ytransaction_commit(txn)
	var n C.uint32_t
	ptr := C.ytransaction_state_vector_v1(txn, &n)
	if ptr == nil {
		return []byte{}, nil
	}
	defer C.ybinary_destroy(ptr, n)
	return C.GoBytes(unsafe.Pointer(ptr), C.int(n)), nil
}

// EncodeStateAsUpdate returns a lib0-v1 update blob carrying the full
// state of the document. Equivalent to state_diff_v1(nil). Use it for
// the snapshot row in note_yjs_snapshots.
func (d *Doc) EncodeStateAsUpdate() ([]byte, error) {
	return d.encodeDiffSince(nil)
}

// EncodeDiffSince returns a lib0-v1 update blob containing only the
// operations the document has that are NOT covered by the supplied
// state vector. This is the SyncStep2 payload in the Yjs y-protocols
// wire protocol — server sends one of these in response to a client's
// SyncStep1 carrying the client's sv. Passing a nil/empty sv is
// equivalent to EncodeStateAsUpdate (full state).
func (d *Doc) EncodeDiffSince(sv []byte) ([]byte, error) {
	return d.encodeDiffSince(sv)
}

func (d *Doc) encodeDiffSince(sv []byte) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, errClosed
	}
	txn := C.ydoc_read_transaction(d.ptr)
	if txn == nil {
		return nil, errors.New("crdt: read transaction unavailable")
	}
	defer C.ytransaction_commit(txn)
	var n C.uint32_t
	var svPtr *C.char
	var svLen C.uint32_t
	if len(sv) > 0 {
		svPtr = (*C.char)(unsafe.Pointer(&sv[0]))
		svLen = C.uint32_t(len(sv))
	}
	ptr := C.ytransaction_state_diff_v1(txn, svPtr, svLen, &n)
	if ptr == nil {
		return []byte{}, nil
	}
	defer C.ybinary_destroy(ptr, n)
	return C.GoBytes(unsafe.Pointer(ptr), C.int(n)), nil
}

// ApplyUpdate applies a lib0-v1 update blob to the document. Safe to
// call repeatedly with overlapping or out-of-order updates: yrs's CRDT
// merge is order-independent.
func (d *Doc) ApplyUpdate(update []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return errClosed
	}
	if len(update) == 0 {
		return nil
	}
	txn := C.ydoc_write_transaction(d.ptr, 0, nil)
	if txn == nil {
		return errors.New("crdt: write transaction unavailable")
	}
	defer C.ytransaction_commit(txn)
	cdata := (*C.char)(unsafe.Pointer(&update[0]))
	rc := C.ytransaction_apply(txn, cdata, C.uint32_t(len(update)))
	if rc != 0 {
		return fmt.Errorf("crdt: ytransaction_apply failed with code %d", int(rc))
	}
	return nil
}

// ---- Textual diff application ----------------------------------------------

// ApplyTextDiff replaces the document content with newText, expressed as
// a single (remove_range, insert) pair at the boundary of the longest
// common prefix and suffix. Returns the lib0-v1 update blob describing
// exactly this change — persist it in note_yjs_updates.
//
// origin is a short label (e.g. "tui-diff", "web") that yrs tags onto
// the produced update; it surfaces in the awareness/observer APIs for
// presence-aware UIs. Empty origin is allowed.
func (d *Doc) ApplyTextDiff(newText string, origin string) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, errClosed
	}

	// Read current text under a read txn so the diff is computed against
	// the same snapshot we then mutate atomically — yrs serialises the
	// next write txn behind us, so the only concurrent edit window is
	// between our two transactions. For lumi-server's single-process
	// model that's adequate; for the live-sync slice (2.3) the read+
	// write will collapse into one composite txn via observer hooks.
	current := readUnderReadTxn(d.ptr, d.contentB)

	// Snapshot state vector for the post-write diff. Same caveat.
	svBefore := stateVectorUnderReadTxn(d.ptr)

	// Compute the minimal middle slice that changed.
	prefixRunes, suffixRunes, oldMid, newMid := diffSlice(current, newText)
	if oldMid == "" && newMid == "" {
		return []byte{}, nil
	}

	insertIndex := utf16Len(prefixRunes)
	removeLen := utf16Len(oldMid)
	_ = suffixRunes // suffix length isn't needed; we operate at insertIndex

	// Open the write transaction, mutate the content branch, capture the
	// produced update, commit.
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

	branch := d.contentB
	if removeLen > 0 {
		C.ytext_remove_range(branch, txn, C.uint32_t(insertIndex), C.uint32_t(removeLen))
	}
	if newMid != "" {
		cval := C.CString(newMid)
		defer C.free(unsafe.Pointer(cval))
		C.ytext_insert(branch, txn, C.uint32_t(insertIndex), cval, nil)
	}

	// Capture the update for this transaction. With a nil sv we'd get
	// the full document state; with svBefore we get just the delta of
	// this write — that's what the update log wants.
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

// ---- Helpers ---------------------------------------------------------------

func readUnderReadTxn(doc *C.YDoc, branch *C.Branch) string {
	txn := C.ydoc_read_transaction(doc)
	if txn == nil {
		return ""
	}
	defer C.ytransaction_commit(txn)
	return readContent(branch, txn)
}

func stateVectorUnderReadTxn(doc *C.YDoc) []byte {
	txn := C.ydoc_read_transaction(doc)
	if txn == nil {
		return nil
	}
	defer C.ytransaction_commit(txn)
	var n C.uint32_t
	ptr := C.ytransaction_state_vector_v1(txn, &n)
	if ptr == nil {
		return nil
	}
	defer C.ybinary_destroy(ptr, n)
	return C.GoBytes(unsafe.Pointer(ptr), C.int(n))
}

// diffSlice finds the common prefix and suffix of two strings (by rune,
// not byte, so we never split a multi-byte codepoint). Returns:
//
//   - prefix runes shared by both,
//   - suffix runes shared by both,
//   - the middle slice of `old` (what to remove),
//   - the middle slice of `new` (what to insert).
//
// Suffix scan stops as soon as it would overlap the prefix.
func diffSlice(old, neu string) (prefix string, suffix string, oldMid string, newMid string) {
	oldRunes := []rune(old)
	newRunes := []rune(neu)

	p := 0
	for p < len(oldRunes) && p < len(newRunes) && oldRunes[p] == newRunes[p] {
		p++
	}

	s := 0
	for s < len(oldRunes)-p && s < len(newRunes)-p &&
		oldRunes[len(oldRunes)-1-s] == newRunes[len(newRunes)-1-s] {
		s++
	}

	prefix = string(oldRunes[:p])
	suffix = string(oldRunes[len(oldRunes)-s:])
	oldMid = string(oldRunes[p : len(oldRunes)-s])
	newMid = string(newRunes[p : len(newRunes)-s])
	return
}

// utf16Len returns the number of UTF-16 code units required to encode s.
// BMP runes are 1 unit; supplementary-plane runes (e.g. most emoji) are
// 2 units (surrogate pair). Matches the JS String.length convention that
// Yjs ytext indices follow.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r > 0xFFFF {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// utf16OfString is exported as a tiny helper for tests; the in-tree
// callers prefer utf16Len. utf16.Encode returns []uint16 which is
// more allocation-heavy than counting code units directly.
func utf16OfString(s string) []uint16 {
	return utf16.Encode([]rune(s))
}
