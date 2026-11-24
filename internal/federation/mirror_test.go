package federation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/wsync"
)

// ---- accept v2 / join ----------------------------------------------------------------

func mirrorInvite(t *testing.T, fx *fedFixture) domain.FederationInvite {
	t.Helper()
	inv, err := fx.svc.CreateInvite(context.Background(), CreateInviteInput{
		VaultID: fx.vault.ID, Actor: fx.vault.OwnerUserID, Mode: ModeMirror,
	})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Mode != ModeMirror || inv.SeverPolicy != SeverKeep {
		t.Fatalf("invite = %+v", inv)
	}
	return inv
}

func signedAcceptV2(t *testing.T, token, followerURL, mode string) AcceptRequest {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return AcceptRequest{
		Token: token, FollowerURL: followerURL, FollowerPubKey: hex.EncodeToString(pub), Mode: mode,
		Signature: hex.EncodeToString(ed25519.Sign(priv, AcceptMessageV2(token, followerURL, mode))),
	}
}

func TestCreateInvite_ModeValidation(t *testing.T) {
	fx := newFedFixture(t, "https://home.example")
	for _, in := range []CreateInviteInput{
		{Mode: "chain"},
		{Mode: ModeReplica, SeverPolicy: SeverPurge},
		{Mode: ModeMirror, SeverPolicy: "shred"},
	} {
		in.VaultID, in.Actor = fx.vault.ID, fx.vault.OwnerUserID
		if _, err := fx.svc.CreateInvite(context.Background(), in); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("%+v: %v", in, err)
		}
	}
}

// Spec A19 #11: a v1 follower presenting a mirror invite gets
// mirror_unsupported and does not burn the invite; the mode is signed and
// read from home's invite row, so neither side can swap it.
func TestAccept_MirrorModeIsSignedAndEnforced(t *testing.T) {
	fx := newFedFixture(t, "https://home.example")
	ctx := context.Background()
	inv := mirrorInvite(t, fx)

	v1, _ := signedAccept(t, inv.Token, "https://mirror.example")
	if _, err := fx.svc.Accept(ctx, v1); !errors.Is(err, domain.ErrMirrorUnsupported) {
		t.Fatalf("v1 follower on a mirror invite: %v", err)
	}
	asReplica := signedAcceptV2(t, inv.Token, "https://mirror.example", ModeReplica)
	if _, err := fx.svc.Accept(ctx, asReplica); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("replica claim on a mirror invite: %v", err)
	}
	// The mode is inside the signature: flipping it breaks it.
	tampered := signedAcceptV2(t, inv.Token, "https://mirror.example", ModeMirror)
	tampered.Mode = ModeReplica
	if _, err := fx.svc.Accept(ctx, tampered); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("tampered mode: %v", err)
	}

	resp, err := fx.svc.Accept(ctx, signedAcceptV2(t, inv.Token, "https://mirror.example", ModeMirror))
	if err != nil {
		t.Fatalf("v2 mirror accept: %v", err)
	}
	if resp.Mode != ModeMirror || resp.SeverPolicy != SeverKeep {
		t.Fatalf("response = %+v", resp)
	}
	rows, _ := fx.feds.ListForVault(ctx, fx.vault.ID)
	if len(rows) != 1 || rows[0].Mode != ModeMirror || rows[0].Role != "home" {
		t.Fatalf("home row = %+v", rows)
	}

	// A replica invite refuses a mirror claim (no downgrade either way).
	rinv := fx.mintInvite(t, "")
	if _, err := fx.svc.Accept(ctx, signedAcceptV2(t, rinv.Token, "https://other.example", ModeMirror)); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("mirror claim on a replica invite: %v", err)
	}
	// ...and still takes v1 and v2-replica followers.
	if _, err := fx.svc.Accept(ctx, signedAcceptV2(t, rinv.Token, "https://other.example", ModeReplica)); err != nil {
		t.Fatalf("v2 replica accept: %v", err)
	}
}

func TestJoin_Mirror(t *testing.T) {
	fx := newFedFixture(t, "https://mirror.example")
	homePub, _, _ := ed25519.GenerateKey(rand.Reader)
	vaultID := uuid.New()
	var got AcceptRequest
	answerMode := ModeMirror
	fx.svc.client = &fakeHome{
		identity: Identity{URL: "https://home.example", PublicKey: hex.EncodeToString(homePub)},
		accept: func(req AcceptRequest) (AcceptResponse, error) {
			got = req
			return AcceptResponse{Vault: VaultInfo{ID: vaultID, Slug: "book", Name: "Book"}, Mode: answerMode, SeverPolicy: SeverKeep}, nil
		},
	}
	ctx := context.Background()
	v, fed, err := fx.svc.Join(ctx, JoinInput{HomeURL: "https://home.example", Token: "tok", Mode: ModeMirror, Actor: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	if got.Mode != ModeMirror {
		t.Fatalf("join did not ask for a mirror: %+v", got)
	}
	sig, _ := hex.DecodeString(got.Signature)
	pub, _ := hex.DecodeString(got.FollowerPubKey)
	if !ed25519.Verify(pub, AcceptMessageV2("tok", "https://mirror.example", ModeMirror), sig) {
		t.Fatal("mirror join must sign the v2 accept")
	}
	if v.ID != vaultID || fed.Mode != ModeMirror || fed.Role != "follower" {
		t.Fatalf("join = %+v %+v", v, fed)
	}
	if !fx.svc.IsMirrorVault(ctx, vaultID) {
		t.Fatal("joined vault is not a mirror")
	}

	// Home answering another mode than asked: refuse to provision.
	answerMode = ModeReplica
	if _, _, err := fx.svc.Join(ctx, JoinInput{HomeURL: "https://home.example", Token: "tok2", Mode: ModeMirror, Actor: uuid.New()}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("mode mismatch: %v", err)
	}
}

// ---- resolver clamp ------------------------------------------------------------------

func TestControlResolver_ClampsMirrorVaults(t *testing.T) {
	fx := newFedFixture(t, "https://mirror.example")
	vaultID := uuid.New()
	admin := domain.Role{Name: "Admin", Capabilities: domain.CapabilitySet{domain.CapAll}}
	resolver := NewControlResolver(staticResolver{role: admin}, &fakeUsersByID{byID: map[uuid.UUID]domain.User{}})
	resolver.Bind(fx.svc)
	ctx := context.Background()
	fed, _ := fx.feds.Insert(ctx, domain.Federation{VaultID: vaultID, Role: "follower", Mode: ModeMirror, PeerURL: "https://home.example", Status: "active"})

	role, err := resolver.RoleForUser(ctx, vaultID, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if !role.MirrorReadOnly || !role.Capabilities.Has(domain.CapNoteRead) || !role.Capabilities.Has(domain.CapVaultExport) {
		t.Fatalf("clamped role = %+v", role)
	}
	for _, c := range []domain.Capability{domain.CapNoteEdit, domain.CapNoteCreate, domain.CapNoteDelete, domain.CapNoteMove,
		domain.CapVaultManage, domain.CapVaultFederate, domain.CapMembersManage, domain.CapMembersInvite, domain.CapRolesManage, domain.CapAuditRead} {
		if role.Capabilities.Has(c) {
			t.Fatalf("mirror role keeps %s", c)
		}
	}

	// Revoked by home (keep policy): still read-only.
	_ = fx.feds.UpdateStatus(ctx, fed.ID, "severed", time.Now())
	resolver.cache.invalidate(vaultID)
	if role, _ := resolver.RoleForUser(ctx, vaultID, uuid.New()); !role.MirrorReadOnly || role.Capabilities.Has(domain.CapNoteEdit) {
		t.Fatalf("severed mirror unclamped: %+v", role)
	}

	// Promoted: writable again.
	row := fx.feds.rows[fed.ID]
	now := time.Now()
	row.PromotedAt = &now
	fx.feds.rows[fed.ID] = row
	resolver.cache.invalidate(vaultID)
	if role, _ := resolver.RoleForUser(ctx, vaultID, uuid.New()); role.MirrorReadOnly || !role.Capabilities.Has(domain.CapNoteEdit) {
		t.Fatalf("promoted mirror still clamped: %+v", role)
	}
}

// Three violations within an hour revoke the link.
func TestMirrorViolation_RevokesAfterThree(t *testing.T) {
	fx := newFedFixture(t, "https://home.example")
	ctx := context.Background()
	fed, _ := fx.feds.Insert(ctx, domain.Federation{VaultID: fx.vault.ID, Role: "home", Mode: ModeMirror, PeerURL: "https://mirror.example", Status: "active"})
	for i := 0; i < 2; i++ {
		fx.svc.MirrorViolation(ctx, fx.vault.ID, "https://mirror.example", "note_sync", "a")
	}
	if fx.feds.rows[fed.ID].Status != "active" {
		t.Fatal("revoked before the third violation")
	}
	fx.svc.MirrorViolation(ctx, fx.vault.ID, "https://mirror.example", "delete", "a")
	if fx.feds.rows[fed.ID].Status != "revoked" {
		t.Fatalf("status after 3 violations = %s", fx.feds.rows[fed.ID].Status)
	}
	n := 0
	for _, a := range fx.audit.actions() {
		if a == domain.ActionFederationMirrorViolation {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("violations audited %d times", n)
	}
}

// ---- relay ------------------------------------------------------------------------------

type mirrorHooks struct {
	mu         sync.Mutex
	acked      int64
	homeSeq    int64
	violations []string
	blocked    []string
	head       atomic.Int64
}

func (h *mirrorHooks) install(home, mirror *relaySide) {
	home.links.deps.MirrorAcked = func(_ uuid.UUID, _ string, seq int64) {
		h.mu.Lock()
		h.acked = seq
		h.mu.Unlock()
	}
	home.links.deps.Head = func(context.Context, uuid.UUID) (int64, error) { return h.head.Load(), nil }
	home.links.deps.MirrorViolation = func(_ context.Context, _ uuid.UUID, _, frame, _ string) {
		h.mu.Lock()
		h.violations = append(h.violations, frame)
		h.mu.Unlock()
	}
	if mirror != nil {
		mirror.links.deps.HomeSeqApplied = func(_ uuid.UUID, _ string, seq int64) {
			h.mu.Lock()
			h.homeSeq = seq
			h.mu.Unlock()
		}
		mirror.links.deps.LocalWriteBlocked = func(_ uuid.UUID, noteID, _ string) {
			h.mu.Lock()
			h.blocked = append(h.blocked, noteID)
			h.mu.Unlock()
		}
	}
}

func (h *mirrorHooks) snapshot() (acked, homeSeq int64, violations, blocked []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.acked, h.homeSeq, append([]string(nil), h.violations...), append([]string(nil), h.blocked...)
}

// mirrorLink connects home and a mirror over a mirror-mode link.
func mirrorLink(t *testing.T, home, mirror *relaySide, vaultID uuid.UUID) (stop func(), hs, ms *Session) {
	t.Helper()
	homeConn, mirrorConn := newPipePair()
	ctx, cancel := context.WithCancel(context.Background())
	hs = home.links.NewSessionWith(ctx, homeConn, vaultID, "https://mirror.example", "home",
		SessionOptions{Mode: ModeMirror, PeerProto: RelayProtoVersion})
	ms = mirror.links.NewSessionWith(ctx, mirrorConn, vaultID, "https://home.example", "follower",
		SessionOptions{Mode: ModeMirror})
	done := make(chan struct{}, 2)
	go func() { _ = hs.Run(); done <- struct{}{} }()
	go func() { _ = ms.Run(); done <- struct{}{} }()
	stopped := false
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		<-done
		<-done
	}
	t.Cleanup(stop)
	return stop, hs, ms
}

// Spec A19 #1, #4: backfill (more notes than the window), live updates,
// live and offline deletes, acks; the mirror never sends content.
func TestMirror_BackfillLiveDeletesAndAcks(t *testing.T) {
	vaultID := uuid.New()
	home, mirror := newRelaySide(t), newRelaySide(t)
	hooks := &mirrorHooks{}
	hooks.install(home, mirror)
	const n = backfillWindow + 8
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("n%02d", i)
		home.seedEpoch(t, vaultID, id, "body "+id, "e-"+id)
	}
	hooks.head.Store(100)
	// The mirror holds a note home no longer has (deleted while away).
	mirror.seedEpoch(t, vaultID, "gone", "stale", "e-gone")

	stop, _, ms := mirrorLink(t, home, mirror, vaultID)
	waitFor(t, "full backfill", func() bool {
		for i := 0; i < n; i++ {
			id := fmt.Sprintf("n%02d", i)
			if text, ok := mirror.mirror.get(vaultID, id); !ok || text != "body "+id {
				return false
			}
		}
		return true
	})
	waitFor(t, "absent note deleted on the mirror", func() bool { return !hasNote(mirror, vaultID, "gone") })
	waitFor(t, "ack of the opening head", func() bool {
		acked, homeSeq, _, _ := hooks.snapshot()
		return acked == 100 && homeSeq == 100
	})
	if p := ms.backfillProgress(); p.Active || p.Synced != n || p.Total != n {
		t.Fatalf("backfill progress = %+v", p)
	}
	if hasNote(home, vaultID, "gone") {
		t.Fatal("mirror's local note reached home")
	}

	// Live edit and delete at home.
	home.localEdit(t, vaultID, "n00", "edited at home")
	waitFor(t, "live edit on the mirror", func() bool {
		text, _ := mirror.mirror.get(vaultID, "n00")
		return text == "edited at home"
	})
	_ = home.notes.delete(vaultID, "n01")
	home.links.NoteDeleted(vaultID, "n01")
	hooks.head.Store(102)
	waitFor(t, "live delete on the mirror", func() bool { return !hasNote(mirror, vaultID, "n01") })
	waitFor(t, "ack follows the head", func() bool { acked, _, _, _ := hooks.snapshot(); return acked == 102 })

	// A write on the mirror that bypassed every guard is not relayed.
	mirror.localEdit(t, vaultID, "n02", "tampered on the mirror")
	time.Sleep(200 * time.Millisecond)
	if got := home.text(t, vaultID, "n02"); got != "body n02" {
		t.Fatalf("mirror content reached home: %q", got)
	}
	if _, _, v, blocked := hooks.snapshot(); len(blocked) == 0 || len(v) != 0 {
		t.Fatalf("local write on the mirror: blocked=%v violations=%v", blocked, v)
	}
	stop()

	// Offline: home deletes; on reconnect the mirror deletes too (G2 for
	// mirrors), even though it was never told live.
	_ = home.notes.delete(vaultID, "n03")
	mirrorLink(t, home, mirror, vaultID)
	waitFor(t, "offline delete reaches the mirror", func() bool { return !hasNote(mirror, vaultID, "n03") })
	if hasNote(home, vaultID, "n03") {
		t.Fatal("home resurrected a note from its mirror")
	}
}

// Spec §A8: home deleted and recreated an id while the mirror was away;
// the mirror drops the old history and takes the new one.
func TestMirror_LineageChangeRebuilds(t *testing.T) {
	vaultID := uuid.New()
	home, mirror := newRelaySide(t), newRelaySide(t)
	(&mirrorHooks{}).install(home, mirror)
	home.seedEpoch(t, vaultID, "alpha", "v2 text", "e-new")
	mirror.seedEpoch(t, vaultID, "alpha", "v1 text", "e-old")
	mirrorLink(t, home, mirror, vaultID)
	waitFor(t, "new lineage on the mirror", func() bool {
		n, err := mirror.notes.Get(context.Background(), vaultID, "alpha")
		text, _ := mirror.mirror.get(vaultID, "alpha")
		return err == nil && n.CRDTEpoch == "e-new" && text == "v2 text"
	})
}

// Spec A19 #3: a mirror that sends content gets its link closed and a
// violation recorded; home's content is unchanged. No-op Step2s and Step1s
// are fine.
func TestMirror_HomeClosesOnContentFromMirror(t *testing.T) {
	cases := []struct {
		name  string
		frame func(home *relaySide, vaultID uuid.UUID, t *testing.T) []byte
	}{
		{"update", func(h *relaySide, v uuid.UUID, t *testing.T) []byte {
			return EncodeNoteSync("alpha", wsync.EncodeSyncUpdate(updateFor(t, h, v, "alpha", "forged")))
		}},
		{"step2", func(h *relaySide, v uuid.UUID, t *testing.T) []byte {
			return EncodeNoteSync("alpha", wsync.EncodeSyncStep2(updateFor(t, h, v, "alpha", "forged")))
		}},
		{"delete", func(*relaySide, uuid.UUID, *testing.T) []byte { return EncodeNoteDelete("alpha") }},
		{"move", func(*relaySide, uuid.UUID, *testing.T) []byte {
			return EncodeNoteMove(NoteMeta{ID: "alpha", Path: "x.md", Title: "x"})
		}},
		{"announce", func(*relaySide, uuid.UUID, *testing.T) []byte {
			return EncodeNoteAnnounce(NoteMeta{ID: "evil", Path: "evil.md", Title: "e"})
		}},
		{"meta2", func(*relaySide, uuid.UUID, *testing.T) []byte {
			return EncodeNoteMeta2(NoteMeta{ID: "alpha", Path: "alpha.md"}, []byte(`{"tags":["x"]}`))
		}},
		{"manifest", func(*relaySide, uuid.UUID, *testing.T) []byte {
			return EncodeManifest([]NoteMeta{{ID: "evil", Path: "evil.md"}})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vaultID := uuid.New()
			home := newRelaySide(t)
			hooks := &mirrorHooks{}
			hooks.install(home, nil)
			home.seedEpoch(t, vaultID, "alpha", "home text", "e1")
			homeConn, peer := newPipePair()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			hs := home.links.NewSessionWith(ctx, homeConn, vaultID, "https://mirror.example", "home",
				SessionOptions{Mode: ModeMirror, PeerProto: RelayProtoVersion})
			go func() { _ = hs.Run() }()
			// Harmless input first: a Step1 and a no-op Step2.
			_ = peer.WriteMessage(binaryMessage, EncodeNoteSync("alpha", wsync.EncodeSyncStep1([]byte{0})))
			_ = peer.WriteMessage(binaryMessage, EncodeNoteSync("alpha", wsync.EncodeSyncStep2([]byte{0, 0})))
			time.Sleep(50 * time.Millisecond)
			select {
			case <-hs.done:
				t.Fatal("link closed on harmless input")
			default:
			}
			_ = peer.WriteMessage(binaryMessage, tc.frame(home, vaultID, t))
			select {
			case <-hs.done:
			case <-time.After(3 * time.Second):
				t.Fatal("link not closed")
			}
			waitFor(t, "violation reported", func() bool { _, _, v, _ := hooks.snapshot(); return len(v) == 1 })
			if got := home.text(t, vaultID, "alpha"); got != "home text" {
				t.Fatalf("home content changed: %q", got)
			}
			if n, _ := home.notes.Get(context.Background(), vaultID, "alpha"); n.Path != "alpha.md" {
				t.Fatalf("home metadata changed: %+v", n)
			}
			if hasNote(home, vaultID, "evil") {
				t.Fatal("mirror created a note at home")
			}
		})
	}
}

// Home never asks a mirror for content: no Step1 in the opening.
func TestMirror_HomeOpeningHasNoStep1(t *testing.T) {
	vaultID := uuid.New()
	home := newRelaySide(t)
	hooks := &mirrorHooks{}
	hooks.install(home, nil)
	hooks.head.Store(7)
	home.seedEpoch(t, vaultID, "alpha", "text", "e1")
	homeConn, peer := newPipePair()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hs := home.links.NewSessionWith(ctx, homeConn, vaultID, "https://mirror.example", "home",
		SessionOptions{Mode: ModeMirror, PeerProto: RelayProtoVersion})
	go func() { _ = hs.Run() }()
	sawHead := false
	deadline := time.After(time.Second)
	for !sawHead {
		select {
		case msg := <-peer.in:
			f, err := DecodeFrame(msg)
			if err != nil {
				t.Fatal(err)
			}
			if f.Type == frameNoteSync {
				t.Fatal("home sent a sync frame to a mirror in the opening")
			}
			if f.Type == frameChangesEnd {
				if f.Seq != 7 {
					t.Fatalf("head = %d", f.Seq)
				}
				sawHead = true
			}
		case <-deadline:
			t.Fatal("no frameChangesEnd in the opening")
		}
	}
}
