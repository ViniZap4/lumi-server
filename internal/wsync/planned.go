package wsync

import (
	"errors"
	"strings"
)

// ErrPlannedOrigin is returned by ApplyPlanned for an origin that is not
// a server-derived op origin.
var ErrPlannedOrigin = errors.New("wsync: planned edits need a server-derived op origin")

// Planned-edit origin prefixes (PHASE3-PROPOSAL C7). The suffix names the
// client ("op:web", "op:tui", "op:apple", "op:cli") or the AI runtime
// ("ai:mcp", "ai:mac", …). Both are derived from the credential on the
// server and recorded as note_yjs_updates.origin_kind.
const (
	OriginOpPrefix = "op:"
	OriginAIPrefix = "ai:"
)

// maxOriginSuffix bounds the client/runtime name of a planned origin.
const maxOriginSuffix = 32

// ValidPlannedOrigin reports whether origin is "op:<name>" or
// "ai:<name>" with name made of 1–32 characters in [a-z0-9-].
func ValidPlannedOrigin(origin string) bool {
	var name string
	switch {
	case strings.HasPrefix(origin, OriginOpPrefix):
		name = origin[len(OriginOpPrefix):]
	case strings.HasPrefix(origin, OriginAIPrefix):
		name = origin[len(OriginAIPrefix):]
	default:
		return false
	}
	if name == "" || len(name) > maxOriginSuffix {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
