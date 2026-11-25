package federation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// fakeMirrorStore answers PendingDeletes/VaultHead for SLA tests.
type fakeMirrorStore struct {
	MirrorStore
	pending int64
	oldest  *time.Time
	head    int64
}

func (f *fakeMirrorStore) PendingDeletes(context.Context, uuid.UUID, int64) (int64, *time.Time, error) {
	return f.pending, f.oldest, nil
}
func (f *fakeMirrorStore) VaultHead(context.Context, uuid.UUID) (int64, error) { return f.head, nil }

// §A8: a mirror whose oldest unacknowledged delete is older than the SLA
// is flagged and audited once per link per day.
func TestErasureSLA_FlagsAndAuditsOncePerDay(t *testing.T) {
	fx := newFedFixture(t, "https://home.example")
	ctx := context.Background()
	now := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	fx.svc.now = func() time.Time { return now }
	old := now.Add(-25 * time.Hour)
	ms := &fakeMirrorStore{pending: 3, oldest: &old, head: 10}
	fx.svc.SetMirrorStore(ms)
	fed, _ := fx.feds.Insert(ctx, domain.Federation{VaultID: fx.vault.ID, Role: "home", Mode: ModeMirror,
		PeerURL: "https://mirror.example", Status: "active", MirrorAckedSeq: 4})
	// A replica link never counts.
	_, _ = fx.feds.Insert(ctx, domain.Federation{VaultID: fx.vault.ID, Role: "home", Mode: ModeReplica,
		PeerURL: "https://replica.example", Status: "active"})

	st := fx.svc.MirrorLinkStats(ctx, fx.feds.rows[fed.ID])
	if !st.ErasureLagging || st.PendingDeletes != 3 || st.LagSeq != 6 {
		t.Fatalf("stats = %+v", st)
	}
	count := func() int {
		n := 0
		for _, a := range fx.audit.actions() {
			if a == domain.ActionFederationErasureLagging {
				n++
			}
		}
		return n
	}
	if got := fx.svc.CheckErasureSLA(ctx); len(got) != 1 || count() != 1 {
		t.Fatalf("lagging = %d, audits = %d", len(got), count())
	}
	fx.svc.CheckErasureSLA(ctx)
	if count() != 1 {
		t.Fatal("alerted twice within a day")
	}
	now = now.Add(25 * time.Hour)
	fx.svc.CheckErasureSLA(ctx)
	if count() != 2 {
		t.Fatal("no new alert the next day")
	}
	// Within the SLA (custom 48 h): not lagging.
	fx.svc.SetErasureSLA(48 * time.Hour)
	recent := now.Add(-2 * time.Hour)
	ms.oldest = &recent
	if st := fx.svc.MirrorLinkStats(ctx, fx.feds.rows[fed.ID]); st.ErasureLagging {
		t.Fatal("flagged inside the SLA")
	}
}

// M3 consent rules at the service: publish needs mirror mode, defaults to
// the flagged scope and to the purge sever policy (D7 a), and travels on
// the accept to the mirror row.
func TestCreateInvite_PublishRules(t *testing.T) {
	fx := newFedFixture(t, "https://home.example")
	ctx := context.Background()
	in := CreateInviteInput{VaultID: fx.vault.ID, Actor: fx.vault.OwnerUserID, Publish: &PublishPolicy{Allowed: true}}
	if _, err := fx.svc.CreateInvite(ctx, in); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("publish on a replica invite: %v", err)
	}
	in.Mode = ModeMirror
	in.Publish = &PublishPolicy{Allowed: true, Scope: "folder:../etc"}
	if _, err := fx.svc.CreateInvite(ctx, in); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("bad scope: %v", err)
	}
	in.Publish = &PublishPolicy{Allowed: true}
	inv, err := fx.svc.CreateInvite(ctx, in)
	if err != nil {
		t.Fatal(err)
	}
	p := UnmarshalPublish(inv.Publish)
	if p == nil || p.Scope != PublishScopeFlagged || inv.SeverPolicy != SeverPurge {
		t.Fatalf("invite = %+v publish=%+v", inv, p)
	}
	resp, err := fx.svc.Accept(ctx, signedAcceptV2(t, inv.Token, "https://pub.example", ModeMirror))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Publish == nil || resp.Publish.Scope != PublishScopeFlagged || resp.SeverPolicy != SeverPurge {
		t.Fatalf("accept = %+v", resp)
	}
	rows, _ := fx.feds.ListForVault(ctx, fx.vault.ID)
	if len(rows) != 1 || UnmarshalPublish(rows[0].Publish) == nil {
		t.Fatalf("home row = %+v", rows)
	}
	// An explicit keep is honoured.
	in.SeverPolicy = SeverKeep
	if inv, err := fx.svc.CreateInvite(ctx, in); err != nil || inv.SeverPolicy != SeverKeep {
		t.Fatalf("keep: %+v %v", inv, err)
	}
}
