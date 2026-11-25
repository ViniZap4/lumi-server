package admin

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

type fakeMirrorOps struct{ calls []string }

func (m *fakeMirrorOps) PauseLink(_ context.Context, id uuid.UUID) (domain.Federation, error) {
	m.calls = append(m.calls, "pause:"+id.String())
	return domain.Federation{ID: id}, nil
}
func (m *fakeMirrorOps) ResumeLink(_ context.Context, id uuid.UUID) (domain.Federation, error) {
	m.calls = append(m.calls, "resume:"+id.String())
	return domain.Federation{ID: id}, nil
}
func (m *fakeMirrorOps) ResyncLink(_ context.Context, id uuid.UUID) (domain.Federation, error) {
	m.calls = append(m.calls, "resync:"+id.String())
	return domain.Federation{ID: id}, nil
}

func TestMirrorAdminRoutes(t *testing.T) {
	h := newHarness(t)
	ops := &fakeMirrorOps{}
	h.svc.Mirrors = ops
	h.svc.Progress = func(uuid.UUID) (BackfillProgress, bool) {
		return BackfillProgress{Active: true, Synced: 3, Total: 9}, true
	}
	v := &Vault{ID: uuid.New(), Slug: "book", Name: "Book", CreatedAt: time.Now()}
	h.store.vaults[v.ID] = v
	home := &Federation{ID: uuid.New(), VaultID: v.ID, VaultSlug: "book", Role: "home", Mode: "mirror", PeerURL: "https://m.example",
		Status: "active", HeadSeq: 40, MirrorAckedSeq: 31, PendingDeletes: 2, CreatedAt: time.Now()}
	replica := &Federation{ID: uuid.New(), VaultID: v.ID, Role: "home", Mode: "replica", PeerURL: "https://r.example", Status: "active", CreatedAt: time.Now()}
	follower := &Federation{ID: uuid.New(), VaultID: uuid.New(), Role: "follower", Mode: "mirror", PeerURL: "https://home.example", Status: "active", HomeSeq: 12, CreatedAt: time.Now()}
	for _, f := range []*Federation{home, replica, follower} {
		h.store.feds[f.ID] = f
	}

	r := h.do(t, "GET", "/admin/v1/federations?mode=mirror", h.token, "")
	if r.status != 200 || strings.Contains(r.body, "r.example") || !strings.Contains(r.body, "m.example") {
		t.Fatalf("mode filter: %d %s", r.status, r.body)
	}
	if r := h.do(t, "GET", "/admin/v1/federations?mode=chain", h.token, ""); r.status != 400 {
		t.Fatalf("bad mode: %d", r.status)
	}
	got := h.do(t, "GET", "/admin/v1/federations/"+home.ID.String(), h.token, "").json(t)
	if got["lag_seq"].(float64) != 9 || got["pending_deletes"].(float64) != 2 || got["mode"] != "mirror" {
		t.Fatalf("home detail %v", got)
	}
	got = h.do(t, "GET", "/admin/v1/federations/"+follower.ID.String(), h.token, "").json(t)
	if bf, _ := got["backfill"].(map[string]any); bf == nil || bf["synced"].(float64) != 3 || bf["total"].(float64) != 9 {
		t.Fatalf("mirror detail %v", got)
	}

	if r := h.do(t, "POST", "/admin/v1/federations/"+home.ID.String()+"/pause", h.token, ""); r.status != 200 {
		t.Fatalf("pause: %d %s", r.status, r.body)
	}
	checkAdminAudit(t, h, ActionFederationPause, nil)
	if r := h.do(t, "POST", "/admin/v1/federations/"+home.ID.String()+"/resume", h.token, ""); r.status != 200 {
		t.Fatalf("resume: %d %s", r.status, r.body)
	}
	checkAdminAudit(t, h, ActionFederationResume, nil)
	// Resync runs on the mirror side only.
	if r := h.do(t, "POST", "/admin/v1/federations/"+home.ID.String()+"/resync", h.token, ""); r.status != 400 {
		t.Fatalf("resync on home side: %d %s", r.status, r.body)
	}
	// Single-note resync needs the running server (the CLI's MirrorOps
	// cannot reach a live session).
	if r := h.do(t, "POST", "/admin/v1/federations/"+follower.ID.String()+"/resync", h.token, `{"note_id":"a"}`); r.status != 409 {
		t.Fatalf("single-note resync without a live relay: %d %s", r.status, r.body)
	}
	if r := h.do(t, "POST", "/admin/v1/federations/"+follower.ID.String()+"/resync", h.token, ""); r.status != 200 {
		t.Fatalf("resync: %d %s", r.status, r.body)
	}
	checkAdminAudit(t, h, ActionMirrorResync, nil)
	want := []string{"pause:" + home.ID.String(), "resume:" + home.ID.String(), "resync:" + follower.ID.String()}
	if strings.Join(ops.calls, ",") != strings.Join(want, ",") {
		t.Fatalf("ops %v", ops.calls)
	}
	// Promotion is not an API route: an admin token cannot fork a book.
	for _, path := range []string{"/admin/v1/federations/" + follower.ID.String() + "/promote", "/admin/v1/vaults/" + v.ID.String() + "/promote"} {
		if r := h.do(t, "POST", path, h.token, ""); r.status != 404 {
			t.Fatalf("POST %s: %d", path, r.status)
		}
	}
}

func TestPromoteMirror(t *testing.T) {
	f := newFixture()
	v := &Vault{ID: uuid.New(), Slug: "book", Name: "Book", CreatedAt: time.Now()}
	f.store.vaults[v.ID] = v
	fed := &Federation{ID: uuid.New(), VaultID: v.ID, Role: "follower", Mode: "mirror", PeerURL: "https://home.example", Status: "active"}
	f.store.feds[fed.ID] = fed
	f.store.promoteState = []byte(`{"members":[]}`)
	ctx := context.Background()
	if _, _, err := f.svc.PromoteMirror(ctx, CLI, "book"); err == nil {
		t.Fatal("promote without a planner")
	}
	f.svc.Planner = func(state []byte) (Promotion, error) {
		return Promotion{Members: []PromotedMember{{Username: "ana", Role: "Editor"}}, Dropped: []string{"bob@https://x.example"}}, nil
	}
	_, res, err := f.svc.PromoteMirror(ctx, CLI, "book")
	if err != nil {
		t.Fatal(err)
	}
	if res.PeerURL != "https://home.example" || len(res.Members) != 1 || len(res.Dropped) != 1 || fed.PromotedAt == nil {
		t.Fatalf("promote = %+v", res)
	}
	if a := f.store.lastAudit(); a.Action != domain.ActionMirrorPromote || !strings.Contains(string(a.Payload), `"token_name":"cli"`) {
		t.Fatalf("promote audit %s %s", a.Action, a.Payload)
	}
	if _, _, err := f.svc.PromoteMirror(ctx, CLI, "book"); err == nil {
		t.Fatal("second promotion accepted")
	}
}

type noteMirrorOps struct {
	fakeMirrorOps
	notes []string
}

func (m *noteMirrorOps) ResyncNote(_ context.Context, id uuid.UUID, noteID string) (domain.Federation, error) {
	m.notes = append(m.notes, id.String()+":"+noteID)
	return domain.Federation{ID: id}, nil
}

func TestMirrorAdmin_SingleNoteResync(t *testing.T) {
	h := newHarness(t)
	ops := &noteMirrorOps{}
	h.svc.Mirrors = ops
	follower := &Federation{ID: uuid.New(), VaultID: uuid.New(), Role: "follower", Mode: "mirror", PeerURL: "https://home.example",
		Status: "active", CreatedAt: time.Now(), Publish: []byte(`{"allowed":true,"scope":"flagged"}`)}
	h.store.feds[follower.ID] = follower
	r := h.do(t, "POST", "/admin/v1/federations/"+follower.ID.String()+"/resync", h.token, `{"note_id":"alpha"}`)
	if r.status != 200 {
		t.Fatalf("note resync: %d %s", r.status, r.body)
	}
	if len(ops.notes) != 1 || ops.notes[0] != follower.ID.String()+":alpha" || len(ops.calls) != 0 {
		t.Fatalf("ops = %v / %v", ops.notes, ops.calls)
	}
	if a := checkAdminAudit(t, h, ActionMirrorResync, nil); !strings.Contains(string(a.Payload), `"note_id":"alpha"`) {
		t.Fatalf("audit payload %s", a.Payload)
	}
	if pub, _ := r.json(t)["publish"].(map[string]any); pub["scope"] != "flagged" {
		t.Fatalf("publish in detail: %s", r.body)
	}
	if r := h.do(t, "POST", "/admin/v1/federations/"+follower.ID.String()+"/resync", h.token, `{"note_id":"`+strings.Repeat("x", 300)+`"}`); r.status != 400 {
		t.Fatalf("long note id: %d", r.status)
	}
}
