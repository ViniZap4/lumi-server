package crdt

import "fmt"

// ThreeWayResult is the outcome of ThreeWayUpdate.
type ThreeWayResult struct {
	// Update holds only the operations that turn the base text into the
	// edited text (lib0 v1). Empty when the edit is a no-op.
	Update []byte
	// BaseText is the text the base state decodes to.
	BaseText string
	// BaseSV is the decoded state vector of the base.
	BaseSV StateVector
}

// ThreeWayUpdate implements the opaque-editor merge (CRDT client protocol
// §7): restore a temporary document from baseState (the full encoded
// state a client fetched from GET /snapshot), diff base text → newText,
// apply those hunks to the temporary document, and return the resulting
// update. Applied to the live document, the update deletes exactly the
// items the user saw and removed, and inserts relative to the items the
// user saw, so concurrent edits made after the base survive (vectors V9b,
// V10) instead of being overwritten (V9a).
//
// baseState must be self-contained: a state with unresolved dependencies
// cannot be rebuilt into text and yields ErrBaseUnreconstructable (which
// wraps ErrBaseMismatch).
func ThreeWayUpdate(baseState []byte, newText string) (ThreeWayResult, error) {
	tmp, err := LoadDoc(baseState)
	if err != nil {
		return ThreeWayResult{}, fmt.Errorf("%w: %v", ErrBaseUnreconstructable, err)
	}
	defer tmp.Close()
	if pending, err := tmp.HasPending(); err != nil {
		return ThreeWayResult{}, err
	} else if pending {
		return ThreeWayResult{}, fmt.Errorf("%w: base state is incomplete", ErrBaseUnreconstructable)
	}
	baseText, err := tmp.Text()
	if err != nil {
		return ThreeWayResult{}, err
	}
	rawSV, err := tmp.StateVectorV1()
	if err != nil {
		return ThreeWayResult{}, err
	}
	sv, err := DecodeStateVector(rawSV)
	if err != nil {
		return ThreeWayResult{}, err
	}
	update, err := tmp.ApplyTextDiff(newText, "lumi:3way")
	if err != nil {
		return ThreeWayResult{}, err
	}
	return ThreeWayResult{Update: update, BaseText: baseText, BaseSV: sv}, nil
}
