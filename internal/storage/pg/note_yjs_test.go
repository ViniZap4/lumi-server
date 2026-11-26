package pg

import (
	"strings"
	"testing"
)

// No Postgres in unit tests: pin the shape of the group-commit INSERT.
// Rows are listed in slice order with five parameters each, so the
// BIGSERIAL ids follow the order the hub applied the updates in.
func TestAppendUpdatesSQL(t *testing.T) {
	got := appendUpdatesSQL(3)
	want := "INSERT INTO note_yjs_updates (vault_id, note_id, update_blob, origin_user_id, origin_kind) VALUES " +
		"($1,$2,$3,$4,$5),($6,$7,$8,$9,$10),($11,$12,$13,$14,$15)"
	if got != want {
		t.Fatalf("got  %s\nwant %s", got, want)
	}
	// A full batch (wsync.DefaultGroupCommitMaxBatch = 256 rows) binds
	// 1280 parameters, far below Postgres's 65535 limit, and ends on the
	// last row's fifth parameter.
	if full := appendUpdatesSQL(256); !strings.HasSuffix(full, ",($1276,$1277,$1278,$1279,$1280)") {
		t.Fatalf("256-row statement ends with %q", full[len(full)-40:])
	}
}
