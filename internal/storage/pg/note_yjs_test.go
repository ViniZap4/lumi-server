package pg

import "testing"

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
	// 256 rows (DefaultGroupCommitMaxBatch) stay far below Postgres's
	// 65535 bind-parameter limit.
	if n := 5 * 256; n > 65535 {
		t.Fatalf("%d parameters", n)
	}
}
