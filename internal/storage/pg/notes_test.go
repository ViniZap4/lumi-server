package pg

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

func n(seq int64) domain.Note { return domain.Note{ID: fmt.Sprintf("n%d", seq), ChangeSeq: seq} }
func tb(seq int64) domain.NoteTombstone {
	return domain.NoteTombstone{ID: fmt.Sprintf("t%d", seq), Seq: seq}
}

func pageSeqs(ns []domain.Note, ts []domain.NoteTombstone) string {
	var out []string
	for _, x := range ns {
		out = append(out, fmt.Sprintf("n%d", x.ChangeSeq))
	}
	for _, x := range ts {
		out = append(out, fmt.Sprintf("t%d", x.Seq))
	}
	return strings.Join(out, ",")
}

func TestMergeChangePage(t *testing.T) {
	cases := []struct {
		name  string
		notes []domain.Note
		tombs []domain.NoteTombstone
		limit int
		want  string
		more  bool
	}{
		{"empty", nil, nil, 5, "", false},
		{"interleaved fits", []domain.Note{n(1), n(4)}, []domain.NoteTombstone{tb(2), tb(3)}, 5, "n1,n4,t2,t3", false},
		{"cut keeps lowest seqs", []domain.Note{n(1), n(4), n(5)}, []domain.NoteTombstone{tb(2), tb(3)}, 3, "n1,t2,t3", true},
		{"exact limit", []domain.Note{n(1)}, []domain.NoteTombstone{tb(2)}, 2, "n1,t2", false},
		{"tombstones only cut", nil, []domain.NoteTombstone{tb(7), tb(8), tb(9)}, 2, "t7,t8", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gn, gt, more := MergeChangePage(tc.notes, tc.tombs, tc.limit)
			if got := pageSeqs(gn, gt); got != tc.want || more != tc.more {
				t.Fatalf("got %q more=%v, want %q more=%v", got, more, tc.want, tc.more)
			}
		})
	}
}

// No Postgres in unit tests: pin the seq contract statically. Every note
// write must take the vault head (bumpHead) inside its transaction BEFORE
// touching notes/tombstones, so writers serialise per vault and commit in
// seq order (SPEC-LIVROS §3.4).
func TestNoteStore_SQLContract(t *testing.T) {
	src, err := os.ReadFile("notes.go")
	if err != nil {
		t.Fatal(err)
	}
	code := string(src)
	for _, fn := range []string{"Upsert", "TouchContent", "Delete"} {
		body := funcBody(t, code, "func (s *NoteStore) "+fn+"(")
		b := strings.Index(body, "bumpHead(ctx, tx,")
		w := regexp.MustCompile(`tx\.Exec\(`).FindStringIndex(body)
		if b < 0 || w == nil || b > w[0] {
			t.Errorf("%s must call bumpHead inside runTx before writing", fn)
		}
		if !strings.Contains(body, "runTx(ctx, s.pool") {
			t.Errorf("%s must run in a transaction", fn)
		}
	}
	if !strings.Contains(code, "ON CONFLICT (vault_id) DO UPDATE\n   SET seq = vault_heads.seq + 1") {
		t.Error("bumpHeadSQL must increment under the row lock")
	}
	ch := funcBody(t, code, "func (s *NoteStore) Changes(")
	if !strings.Contains(ch, "pgx.RepeatableRead") {
		t.Error("Changes must read head and rows in one snapshot")
	}
	if strings.Contains(strings.ToUpper(ch), "OFFSET") {
		t.Error("Changes must paginate by cursor, never OFFSET")
	}
}

func TestMigration0006_UpDown(t *testing.T) {
	up, err := os.ReadFile("../../../migrations/0006_vault_feed.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../../migrations/0006_vault_feed.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"CREATE TABLE vault_heads", "tombstone_floor", "ALTER TABLE notes ADD COLUMN change_seq",
		"CREATE INDEX notes_vault_change_seq_idx ON notes (vault_id, change_seq)",
		"CREATE TABLE note_tombstones", "ON CONFLICT (vault_id) DO NOTHING",
	} {
		if !strings.Contains(string(up), want) {
			t.Errorf("up migration lacks %q", want)
		}
	}
	for _, want := range []string{"DROP TABLE note_tombstones", "DROP COLUMN change_seq", "DROP TABLE vault_heads"} {
		if !strings.Contains(string(down), want) {
			t.Errorf("down migration lacks %q", want)
		}
	}
}

// The CRDT epoch contract (protocol §12), pinned statically like the seq
// contract above: Upsert writes crdt_epoch on INSERT only, and the seed
// path rotates it together with the snapshot and the update log in one
// transaction, taking the vault head before touching the notes row.
func TestNoteStore_EpochSQLContract(t *testing.T) {
	src, err := os.ReadFile("notes.go")
	if err != nil {
		t.Fatal(err)
	}
	up := funcBody(t, string(src), "func (s *NoteStore) Upsert(")
	if !strings.Contains(up, "change_seq, crdt_epoch)") || !strings.Contains(up, "domain.NewCRDTEpoch()") {
		t.Error("Upsert must insert crdt_epoch (fresh when empty)")
	}
	conflict := up[strings.Index(up, "ON CONFLICT"):]
	if strings.Contains(conflict[:strings.Index(conflict, "`")], "crdt_epoch") {
		t.Error("Upsert must not change crdt_epoch on conflict (moves keep the lineage)")
	}
	if !strings.Contains(string(src), "change_seq, crdt_epoch`") {
		t.Error("noteCols must select crdt_epoch")
	}

	ysrc, err := os.ReadFile("note_yjs.go")
	if err != nil {
		t.Fatal(err)
	}
	seed := funcBody(t, string(ysrc), "func (s *NoteYjsStore) SeedSnapshot(")
	for _, want := range []string{
		"runTx(ctx, s.pool",
		"DELETE FROM note_yjs_updates WHERE vault_id = $1 AND note_id = $2`",
		"UPDATE notes SET crdt_epoch = $3, change_seq = $4",
		"INSERT INTO note_yjs_snapshots",
	} {
		if !strings.Contains(seed, want) {
			t.Errorf("SeedSnapshot lacks %q", want)
		}
	}
	b := strings.Index(seed, "bumpHead(ctx, tx,")
	w := strings.Index(seed, "UPDATE notes SET crdt_epoch")
	if b < 0 || b > w {
		t.Error("SeedSnapshot must take the vault head before writing the notes row")
	}
}

func TestMigration0008_UpDown(t *testing.T) {
	up, err := os.ReadFile("../../../migrations/0008_crdt_epoch.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("../../../migrations/0008_crdt_epoch.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	u := string(up)
	add := strings.Index(u, "ALTER TABLE notes ADD COLUMN crdt_epoch TEXT;")
	fill := strings.Index(u, "UPDATE notes SET crdt_epoch = replace(gen_random_uuid()::text, '-', '');")
	notNull := strings.Index(u, "SET NOT NULL")
	if add < 0 || fill < add || notNull < fill {
		t.Errorf("up migration must add the column, backfill every row with a fresh epoch, then set NOT NULL")
	}
	if !strings.Contains(u, "SET DEFAULT replace(gen_random_uuid()::text, '-', '')") {
		t.Error("up migration lacks the random default")
	}
	if !strings.Contains(string(down), "ALTER TABLE notes DROP COLUMN IF EXISTS crdt_epoch") {
		t.Error("down migration must drop crdt_epoch")
	}
}

func funcBody(t *testing.T, code, sig string) string {
	t.Helper()
	i := strings.Index(code, sig)
	if i < 0 {
		t.Fatalf("missing %s", sig)
	}
	rest := code[i:]
	if j := strings.Index(rest[1:], "\nfunc "); j >= 0 {
		return rest[:j+1]
	}
	return rest
}
