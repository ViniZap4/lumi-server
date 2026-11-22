package federation

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

type recordingLinks struct {
	mu      sync.Mutex
	stopped []string
}

func (r *recordingLinks) StartLink(context.Context, uuid.UUID, string) {}
func (r *recordingLinks) StopLink(vaultID uuid.UUID, peerURL string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopped = append(r.stopped, loopKey(vaultID, peerURL))
}

type revokePair struct {
	home, follower *fedFixture
	homeRow        domain.Federation
	followerRow    domain.Federation
	notices        chan RevokeNotice
	followerLinks  *recordingLinks
}

const (
	pairHomeURL     = "https://home.example"
	pairFollowerURL = "https://follower.example"
)

func newRevokePair(t *testing.T) *revokePair {
	t.Helper()
	home := newFedFixture(t, pairHomeURL)
	inv := home.mintInvite(t, "")
	homeIdent, _ := home.svc.Identity()
	follower := newFedFixture(t, pairFollowerURL)
	follower.svc.client = &fakeHome{
		identity: homeIdent,
		accept: func(req AcceptRequest) (AcceptResponse, error) {
			return home.svc.Accept(context.Background(), req)
		},
	}
	_, frow, err := follower.svc.Join(context.Background(), JoinInput{HomeURL: pairHomeURL, Token: inv.Token, Actor: uuid.New()})
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	hrows, _ := home.feds.ListForVault(context.Background(), home.vault.ID)
	p := &revokePair{
		home: home, follower: follower, homeRow: hrows[0], followerRow: frow,
		notices: make(chan RevokeNotice, 4), followerLinks: &recordingLinks{},
	}
	home.svc.client = &fakeHome{notified: p.notices}
	follower.svc.SetLinkController(p.followerLinks)
	return p
}

func (p *revokePair) revokeAtHome(t *testing.T) RevokeNotice {
	t.Helper()
	if err := p.home.svc.RevokeFederation(context.Background(), p.home.vault.ID, p.homeRow.ID, p.home.vault.OwnerUserID, "", ""); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	select {
	case n := <-p.notices:
		return n
	case <-time.After(2 * time.Second):
		t.Fatal("home did not push a revoke notice")
		return RevokeNotice{}
	}
}

func (p *revokePair) followerStatus(t *testing.T) string {
	t.Helper()
	row, err := p.follower.feds.Get(context.Background(), p.followerRow.ID)
	if err != nil {
		t.Fatal(err)
	}
	return row.Status
}

func TestRevokeNotice_PushSeversFollower(t *testing.T) {
	p := newRevokePair(t)
	n := p.revokeAtHome(t)
	if n.VaultID != p.home.vault.ID || n.HomeURL != pairHomeURL || n.FollowerURL != pairFollowerURL {
		t.Fatalf("notice = %+v", n)
	}
	if err := p.follower.svc.ApplyRevokeNotice(context.Background(), n); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := p.followerStatus(t); got != "severed" {
		t.Fatalf("follower status = %q, want severed", got)
	}
	if len(p.followerLinks.stopped) != 1 || p.followerLinks.stopped[0] != loopKey(p.home.vault.ID, pairHomeURL) {
		t.Fatalf("follower link not stopped: %v", p.followerLinks.stopped)
	}
	if !containsAction(p.follower.audit.actions(), domain.ActionFederationRevoke) {
		t.Fatal("severing must be audited")
	}
	// Redelivery (retry, or push + pull) is idempotent.
	if err := p.follower.svc.ApplyRevokeNotice(context.Background(), n); err != nil {
		t.Fatalf("second apply: %v", err)
	}
}

func TestRevokeNotice_RejectsForgeriesAndMismatches(t *testing.T) {
	p := newRevokePair(t)
	n := p.revokeAtHome(t)

	_, otherPriv, _ := ed25519.GenerateKey(nil)
	forged := n
	forged.Signature = hex.EncodeToString(ed25519.Sign(otherPriv,
		RevokeNoticeMessage(n.VaultID, n.HomeURL, n.FollowerURL, n.RevokedAt)))

	otherVault := n
	otherVault.VaultID = uuid.New()

	shifted := n
	shifted.RevokedAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)

	wrongFollower := n
	wrongFollower.FollowerURL = "https://someone-else.example"

	for name, bad := range map[string]RevokeNotice{
		"foreign key":    forged,
		"other vault":    otherVault,
		"altered time":   shifted,
		"wrong follower": wrongFollower,
	} {
		if err := p.follower.svc.ApplyRevokeNotice(context.Background(), bad); !errors.Is(err, domain.ErrForbidden) {
			t.Errorf("%s: err = %v, want ErrForbidden", name, err)
		}
	}
	if got := p.followerStatus(t); got != "active" {
		t.Fatalf("follower status = %q after forgeries, want active", got)
	}
}

// A notice for an old link must not sever a later re-join with the same home.
func TestRevokeNotice_NoReplayAgainstLaterLink(t *testing.T) {
	p := newRevokePair(t)
	n := p.revokeAtHome(t)
	row := p.follower.feds.rows[p.followerRow.ID]
	row.CreatedAt = time.Now().Add(revokeSkew + time.Hour)
	p.follower.feds.rows[p.followerRow.ID] = row
	if err := p.follower.svc.ApplyRevokeNotice(context.Background(), n); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("err = %v, want ErrForbidden", err)
	}
	if got := p.followerStatus(t); got != "active" {
		t.Fatalf("status = %q, want active", got)
	}
}

func TestRevokeNotice_PullRequiresStatusProof(t *testing.T) {
	p := newRevokePair(t)
	p.revokeAtHome(t)
	ctx := context.Background()
	vid := p.home.vault.ID
	ts := time.Now().Unix()
	good := hex.EncodeToString(ed25519.Sign(p.follower.svc.priv, StatusProofMessage(vid, pairFollowerURL, ts)))
	_, otherPriv, _ := ed25519.GenerateKey(nil)
	foreign := hex.EncodeToString(ed25519.Sign(otherPriv, StatusProofMessage(vid, pairFollowerURL, ts)))
	stale := time.Now().Add(-time.Hour).Unix()
	staleSig := hex.EncodeToString(ed25519.Sign(p.follower.svc.priv, StatusProofMessage(vid, pairFollowerURL, stale)))

	if _, ok := p.home.svc.revokedNoticeFor(ctx, vid, pairFollowerURL, 0, ""); ok {
		t.Error("no proof must not disclose revocation")
	}
	if _, ok := p.home.svc.revokedNoticeFor(ctx, vid, pairFollowerURL, ts, foreign); ok {
		t.Error("foreign key proof accepted")
	}
	if _, ok := p.home.svc.revokedNoticeFor(ctx, vid, pairFollowerURL, stale, staleSig); ok {
		t.Error("stale proof accepted")
	}
	n, ok := p.home.svc.revokedNoticeFor(ctx, vid, pairFollowerURL, ts, good)
	if !ok {
		t.Fatal("valid proof refused")
	}
	if err := p.follower.svc.ApplyRevokeNotice(ctx, n); err != nil {
		t.Fatalf("pulled notice rejected: %v", err)
	}
}

// The follower dial loop learns about a revoke it missed from the
// sync-challenge 410 and stops for good.
func TestRelayManager_SeversOnRevokedChallenge(t *testing.T) {
	p := newRevokePair(t)
	p.revokeAtHome(t) // push notice dropped: follower was "offline"
	ctx := context.Background()
	p.follower.svc.client = &fakeHome{challenge: func(req ChallengeRequest) (string, error) {
		if n, ok := p.home.svc.revokedNoticeFor(ctx, req.VaultID, req.PeerURL, req.TS, req.Sig); ok {
			return "", &RevokedError{Notice: n}
		}
		return "", errors.New("forbidden")
	}}
	m := &Manager{svc: p.follower.svc, log: zerolog.Nop(), loops: map[string]context.CancelFunc{}}
	err := m.connectOnce(ctx, p.home.vault.ID, pairHomeURL)
	if !errors.Is(err, errLinkInactive) {
		t.Fatalf("connectOnce err = %v, want errLinkInactive", err)
	}
	if got := p.followerStatus(t); got != "severed" {
		t.Fatalf("follower status = %q, want severed", got)
	}
	// And the loop exits instead of retrying.
	done := make(chan struct{})
	go func() { m.runLoop(ctx, p.home.vault.ID, pairHomeURL); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runLoop kept retrying an inactive link")
	}
}
