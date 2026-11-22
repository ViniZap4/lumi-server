package federation

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/members"
)

// gatedMemberLister snapshots membership, then (on the first call only)
// parks until released — forcing a rebuild to hold a stale snapshot while
// membership changes underneath it.
type gatedMemberLister struct {
	mu      sync.Mutex
	rows    []members.MemberJoined
	calls   int
	started chan struct{}
	release chan struct{}
}

func (g *gatedMemberLister) List(context.Context, uuid.UUID) ([]members.MemberJoined, error) {
	g.mu.Lock()
	snap := append([]members.MemberJoined(nil), g.rows...)
	g.calls++
	first := g.calls == 1
	g.mu.Unlock()
	if first {
		close(g.started)
		<-g.release
	}
	return snap, nil
}

func (g *gatedMemberLister) add(m members.MemberJoined) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.rows = append(g.rows, m)
}

type rebuildResult struct {
	state []byte
	seq   int64
	err   error
}

// TestRebuildControlState_SerialisedPerVault is the regression test for
// the read-then-write seq race: two concurrent rebuilds used to sign the
// same seq from different snapshots, and the one that lost persistence
// was still returned (and pushed) as if authoritative.
func TestRebuildControlState_SerialisedPerVault(t *testing.T) {
	cf := newControlFixture(t)
	cf.federate(t)
	vaultID := cf.home.vault.ID

	g := &gatedMemberLister{
		rows:    []members.MemberJoined{{User: domain.User{Username: "alice"}, Role: cf.adminRole}},
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	cf.home.svc.control.Members = g

	results := make(chan rebuildResult, 2)
	run := func() {
		st, _, seq, err := cf.home.svc.RebuildControlState(context.Background(), vaultID)
		results <- rebuildResult{st, seq, err}
	}
	go run() // A: takes the stale snapshot and parks
	<-g.started
	g.add(members.MemberJoined{User: domain.User{Username: "carol"}, Role: cf.editorRole})
	go run() // B: sees carol
	time.Sleep(50 * time.Millisecond)
	close(g.release)

	a, b := <-results, <-results
	if a.err != nil || b.err != nil {
		t.Fatalf("rebuild errors: %v / %v", a.err, b.err)
	}
	if a.seq == b.seq {
		t.Fatalf("concurrent rebuilds produced the same seq %d", a.seq)
	}

	// Every returned document must be one that was persisted, and the
	// latest persisted document must reflect the newest membership.
	storedSeq, stored, _, err := cf.home.svc.control.States.Get(context.Background(), vaultID)
	if err != nil {
		t.Fatal(err)
	}
	latest := a
	if b.seq > a.seq {
		latest = b
	}
	if storedSeq != latest.seq || string(stored) != string(latest.state) {
		t.Fatalf("highest returned doc (seq %d) is not the persisted one (seq %d)", latest.seq, storedSeq)
	}
	var doc ControlState
	if err := json.Unmarshal(stored, &doc); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, m := range doc.Members {
		if m.Key == cf.home.svc.MemberKey("carol") {
			found = true
		}
	}
	if !found {
		t.Fatalf("persisted control state is stale (no carol): %+v", doc.Members)
	}
}

// When a write loses the conditional upsert (another writer advanced seq),
// RebuildControlState must return the stored document, never its own
// unpersisted one.
func TestRebuildControlState_ReturnsPersistedOnLostUpsert(t *testing.T) {
	cf := newControlFixture(t)
	cf.federate(t)
	vaultID := cf.home.vault.ID
	states := cf.home.svc.control.States.(*memControlStates)
	racing := &racingStates{memControlStates: states, bumpTo: 7, bumpState: []byte(`{"v":1,"seq":7}`), bumpSig: []byte("sig7")}
	cf.home.svc.control.States = racing

	st, sig, seq, err := cf.home.svc.RebuildControlState(context.Background(), vaultID)
	if err != nil {
		t.Fatal(err)
	}
	if seq != 7 || string(st) != `{"v":1,"seq":7}` || string(sig) != "sig7" {
		t.Fatalf("got seq=%d state=%s; want the persisted seq 7 doc", seq, st)
	}
}

// racingStates simulates another process persisting a higher seq between
// our Get and Upsert.
type racingStates struct {
	*memControlStates
	bumpTo    int64
	bumpState []byte
	bumpSig   []byte
	bumped    bool
}

func (r *racingStates) Upsert(ctx context.Context, vaultID uuid.UUID, seq int64, state, sig []byte) (bool, error) {
	if !r.bumped {
		r.bumped = true
		if _, err := r.memControlStates.Upsert(ctx, vaultID, r.bumpTo, r.bumpState, r.bumpSig); err != nil {
			return false, err
		}
	}
	return r.memControlStates.Upsert(ctx, vaultID, seq, state, sig)
}
