package domain

import (
	"crypto/rand"
	"encoding/hex"
)

// NewCRDTEpoch returns a fresh, opaque CRDT lineage identifier: 128 random
// bits as 32 lowercase hex characters. Clients compare epochs only for
// equality; the format is not part of the contract.
func NewCRDTEpoch() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand.Read never fails on supported platforms (Go 1.24+
		// crashes the program instead); keep the panic for older ones.
		panic("domain: crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
