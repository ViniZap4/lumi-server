package federation

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/members"
)

// ---- control-plane fakes -----------------------------------------------------------

type memControlStates struct {
	mu   sync.Mutex
	rows map[uuid.UUID]struct {
		seq        int64
		state, sig []byte
	}
}

func newMemControlStates() *memControlStates {
	return &memControlStates{rows: map[uuid.UUID]struct {
		seq        int64
		state, sig []byte
	}{}}
}

func (m *memControlStates) Get(_ context.Context, vaultID uuid.UUID) (int64, []byte, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[vaultID]
	if !ok {
		return 0, nil, nil, domain.ErrNotFound
	}
	return r.seq, r.state, r.sig, nil
}

func (m *memControlStates) Upsert(_ context.Context, vaultID uuid.UUID, seq int64, state, sig []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cur, ok := m.rows[vaultID]; ok && cur.seq >= seq {
		return nil
	}
	m.rows[vaultID] = struct {
		seq        int64
		state, sig []byte
	}{seq, state, sig}
	return nil
}

type memReplicated struct {
	mu   sync.Mutex
	rows map[uuid.UUID]struct {
		seq   int64
		state []byte
	}
}

func newMemReplicated() *memReplicated {
	return &memReplicated{rows: map[uuid.UUID]struct {
		seq   int64
		state []byte
	}{}}
}

func (m *memReplicated) Get(_ context.Context, vaultID uuid.UUID) (int64, []byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[vaultID]
	if !ok {
		return 0, nil, domain.ErrNotFound
	}
	return r.seq, r.state, nil
}

func (m *memReplicated) Upsert(_ context.Context, vaultID uuid.UUID, seq int64, state []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cur, ok := m.rows[vaultID]; ok && cur.seq >= seq {
		return nil
	}
	m.rows[vaultID] = struct {
		seq   int64
		state []byte
	}{seq, state}
	return nil
}

type memFedMembers struct {
	mu   sync.Mutex
	rows map[string]FederatedMember // vault|key
}

func newMemFedMembers() *memFedMembers { return &memFedMembers{rows: map[string]FederatedMember{}} }

func fmKey(vaultID uuid.UUID, key string) string { return vaultID.String() + "|" + key }

func (m *memFedMembers) Add(_ context.Context, vaultID uuid.UUID, memberKey string, roleID uuid.UUID, _ uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[fmKey(vaultID, memberKey)] = FederatedMember{MemberKey: memberKey, RoleID: roleID, RoleName: "Editor", JoinedAt: time.Now()}
	return nil
}

func (m *memFedMembers) ChangeRole(_ context.Context, vaultID uuid.UUID, memberKey string, roleID uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rows[fmKey(vaultID, memberKey)]
	if !ok {
		return domain.ErrNotFound
	}
	r.RoleID = roleID
	m.rows[fmKey(vaultID, memberKey)] = r
	return nil
}

func (m *memFedMembers) Remove(_ context.Context, vaultID uuid.UUID, memberKey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := fmKey(vaultID, memberKey)
	if _, ok := m.rows[k]; !ok {
		return domain.ErrNotFound
	}
	delete(m.rows, k)
	return nil
}

func (m *memFedMembers) ListForVault(_ context.Context, vaultID uuid.UUID) ([]FederatedMember, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []FederatedMember
	for k, r := range m.rows {
		if len(k) > 36 && k[:36] == vaultID.String() {
			out = append(out, r)
		}
	}
	return out, nil
}

type fakeMemberLister struct {
	rows []members.MemberJoined
}

func (f *fakeMemberLister) List(context.Context, uuid.UUID) ([]members.MemberJoined, error) {
	return f.rows, nil
}

type fakeRoleLister struct {
	roles []domain.Role
}

func (f *fakeRoleLister) ListForVault(context.Context, uuid.UUID) ([]domain.Role, error) {
	return f.roles, nil
}

func (f *fakeRoleLister) Get(_ context.Context, _, roleID uuid.UUID) (domain.Role, error) {
	for _, r := range f.roles {
		if r.ID == roleID {
			return r, nil
		}
	}
	return domain.Role{}, domain.ErrNotFound
}

type fakeAcks struct {
	mu   sync.Mutex
	last map[string]int64
}

func (f *fakeAcks) UpdateLastAcked(_ context.Context, vaultID uuid.UUID, peerURL string, seq int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.last == nil {
		f.last = map[string]int64{}
	}
	k := vaultID.String() + "|" + peerURL
	if seq > f.last[k] {
		f.last[k] = seq
	}
	return nil
}

type fakeUsersByID struct {
	byID map[uuid.UUID]domain.User
}

func (f *fakeUsersByID) GetByID(_ context.Context, id uuid.UUID) (domain.User, error) {
	u, ok := f.byID[id]
	if !ok {
		return domain.User{}, domain.ErrNotFound
	}
	return u, nil
}

type staticResolver struct{ role domain.Role }

func (s staticResolver) RoleForUser(context.Context, uuid.UUID, uuid.UUID) (domain.Role, error) {
	return s.role, nil
}

// controlFixture: a home service + a follower service federated over fakes.
type controlFixture struct {
	home, follower *fedFixture
	adminRole      domain.Role
	editorRole     domain.Role
	homeMembers    *fakeMemberLister
	fedMembers     *memFedMembers
	followerRepl   *memReplicated
	acks           *fakeAcks
}

func newControlFixture(t *testing.T) *controlFixture {
	t.Helper()
	home := newFedFixture(t, "https://home.example")
	follower := newFedFixture(t, "https://follower.example")

	admin := domain.Role{ID: uuid.New(), VaultID: home.vault.ID, Name: "Admin", Capabilities: domain.CapabilitySet{domain.CapAll}, IsSeed: true}
	editor := domain.Role{ID: uuid.New(), VaultID: home.vault.ID, Name: "Editor", Capabilities: domain.CapabilitySet{domain.CapNoteRead, domain.CapNoteEdit}, IsSeed: true}

	homeMembers := &fakeMemberLister{rows: []members.MemberJoined{
		{User: domain.User{Username: "alice"}, Role: admin},
	}}
	fedMembers := newMemFedMembers()
	acks := &fakeAcks{}
	home.svc.SetControlPlane(ControlPlaneDeps{
		States:     newMemControlStates(),
		Replicated: newMemReplicated(),
		FedMembers: fedMembers,
		Members:    homeMembers,
		Roles:      &fakeRoleLister{roles: []domain.Role{admin, editor}},
		Acks:       acks,
	})

	followerRepl := newMemReplicated()
	follower.svc.SetControlPlane(ControlPlaneDeps{
		States:     newMemControlStates(),
		Replicated: followerRepl,
		FedMembers: newMemFedMembers(),
		Members:    &fakeMemberLister{},
		Roles:      &fakeRoleLister{},
		Acks:       &fakeAcks{},
	})

	return &controlFixture{
		home: home, follower: follower,
		adminRole: admin, editorRole: editor,
		homeMembers: homeMembers, fedMembers: fedMembers,
		followerRepl: followerRepl, acks: acks,
	}
}

// federate runs the real F1 handshake so both sides hold each other's keys.
func (cf *controlFixture) federate(t *testing.T) uuid.UUID {
	t.Helper()
	inv := cf.home.mintInvite(t, "")
	homeIdent, _ := cf.home.svc.Identity()
	cf.follower.svc.client = &fakeHome{
		identity: homeIdent,
		accept: func(req AcceptRequest) (AcceptResponse, error) {
			return cf.home.svc.Accept(context.Background(), req)
		},
	}
	replica, _, err := cf.follower.svc.Join(context.Background(), JoinInput{
		HomeURL: "https://home.example",
		Token:   inv.Token,
		Actor:   uuid.New(),
	})
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	// The follower fixture's vault lookup must know the replica row.
	cf.follower.vaults.rows[replica.ID] = domain.Vault{ID: replica.ID, Slug: replica.Slug, Name: replica.Name}
	return replica.ID
}

// ---- build / apply -------------------------------------------------------------------

func TestControlState_BuildSignApplyRoundTrip(t *testing.T) {
	cf := newControlFixture(t)
	vaultID := cf.federate(t)

	// Home authors: alice (local admin) + bob@follower as Editor.
	if err := cf.fedMembers.Add(context.Background(), cf.home.vault.ID, "bob@https://follower.example", cf.editorRole.ID, uuid.New()); err != nil {
		t.Fatal(err)
	}
	state, sig, seq, err := cf.home.svc.RebuildControlState(context.Background(), cf.home.vault.ID)
	if err != nil || seq != 1 || len(state) == 0 || len(sig) == 0 {
		t.Fatalf("rebuild: seq=%d err=%v", seq, err)
	}

	// Follower verifies + applies (vault IDs match across servers).
	got, err := cf.follower.svc.ApplyControlState(context.Background(), vaultID, "https://home.example", state, sig)
	if err != nil || got != 1 {
		t.Fatalf("apply: seq=%d err=%v", got, err)
	}

	// Stale replay acks the real cursor without regressing.
	got, err = cf.follower.svc.ApplyControlState(context.Background(), vaultID, "https://home.example", state, sig)
	if err != nil || got != 1 {
		t.Fatalf("stale apply: seq=%d err=%v", got, err)
	}
}

func TestControlState_RejectsBadSignatureAndWrongPeer(t *testing.T) {
	cf := newControlFixture(t)
	vaultID := cf.federate(t)
	state, sig, _, err := cf.home.svc.RebuildControlState(context.Background(), cf.home.vault.ID)
	if err != nil {
		t.Fatal(err)
	}

	tampered := append([]byte{}, state...)
	tampered[len(tampered)-2] ^= 0xff
	if _, err := cf.follower.svc.ApplyControlState(context.Background(), vaultID, "https://home.example", tampered, sig); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("tampered state must be forbidden, got %v", err)
	}
	if _, err := cf.follower.svc.ApplyControlState(context.Background(), vaultID, "https://unknown.example", state, sig); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("unknown peer must be forbidden, got %v", err)
	}
}

func TestControlState_SkipsUnfederatedVaults(t *testing.T) {
	cf := newControlFixture(t)
	// No federate() — home has no active home-role link.
	state, sig, seq, err := cf.home.svc.RebuildControlState(context.Background(), cf.home.vault.ID)
	if err != nil || state != nil || sig != nil || seq != 0 {
		t.Fatalf("unfederated vault must skip: %v %v %d %v", state, sig, seq, err)
	}
}

// ---- resolver ---------------------------------------------------------------------------

func TestControlResolver_ReplicatedGrantsAndRevocations(t *testing.T) {
	cf := newControlFixture(t)
	vaultID := cf.federate(t)

	bobID := uuid.New()
	users := &fakeUsersByID{byID: map[uuid.UUID]domain.User{
		bobID: {ID: bobID, Username: "bob"},
	}}
	localRole := domain.Role{Name: "LocalAdmin", Capabilities: domain.CapabilitySet{domain.CapAll}}
	resolver := NewControlResolver(staticResolver{role: localRole}, users)
	resolver.Bind(cf.follower.svc)

	// Bootstrap window: no replicated state yet → local membership answers.
	role, err := resolver.RoleForUser(context.Background(), vaultID, bobID)
	if err != nil || role.Name != "LocalAdmin" {
		t.Fatalf("bootstrap must fall back to base: %v %v", role, err)
	}

	// Home grants bob@follower Editor and pushes state.
	if err := cf.fedMembers.Add(context.Background(), cf.home.vault.ID, "bob@https://follower.example", cf.editorRole.ID, uuid.New()); err != nil {
		t.Fatal(err)
	}
	state, sig, _, err := cf.home.svc.RebuildControlState(context.Background(), cf.home.vault.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cf.follower.svc.ApplyControlState(context.Background(), vaultID, "https://home.example", state, sig); err != nil {
		t.Fatal(err)
	}

	role, err = resolver.RoleForUser(context.Background(), vaultID, bobID)
	if err != nil || role.Name != "Editor" {
		t.Fatalf("replicated grant expected Editor, got %v %v", role, err)
	}
	if !role.Capabilities.Has(domain.CapNoteEdit) || role.Capabilities.Has(domain.CapVaultManage) {
		t.Fatalf("replicated capabilities wrong: %v", role.Capabilities)
	}

	// Home revokes bob; new state applies; the resolver cache must be
	// invalidated by ApplyControlState so revocation is immediate.
	if err := cf.fedMembers.Remove(context.Background(), cf.home.vault.ID, "bob@https://follower.example"); err != nil {
		t.Fatal(err)
	}
	state, sig, _, err = cf.home.svc.RebuildControlState(context.Background(), cf.home.vault.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cf.follower.svc.ApplyControlState(context.Background(), vaultID, "https://home.example", state, sig); err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.RoleForUser(context.Background(), vaultID, bobID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("revoked user must get ErrNotFound, got %v", err)
	}

	// A user not in the member list never gets in.
	strangerID := uuid.New()
	users.byID[strangerID] = domain.User{ID: strangerID, Username: "mallory"}
	if _, err := resolver.RoleForUser(context.Background(), vaultID, strangerID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("stranger must get ErrNotFound, got %v", err)
	}
}

func TestControlResolver_UnfederatedVaultUsesBase(t *testing.T) {
	cf := newControlFixture(t)
	localRole := domain.Role{Name: "Viewer"}
	resolver := NewControlResolver(staticResolver{role: localRole}, &fakeUsersByID{byID: map[uuid.UUID]domain.User{}})
	resolver.Bind(cf.follower.svc)

	role, err := resolver.RoleForUser(context.Background(), uuid.New(), uuid.New())
	if err != nil || role.Name != "Viewer" {
		t.Fatalf("plain vault must use base resolver: %v %v", role, err)
	}
}

// ---- federated member admin ------------------------------------------------------------

func TestFederatedMembers_ValidationAndAudit(t *testing.T) {
	cf := newControlFixture(t)
	cf.federate(t)
	actor := uuid.New()

	for _, bad := range []string{"", "bob", "@https://x.example", "bob@", "bob@not-a-url"} {
		if err := cf.home.svc.AddFederatedMember(context.Background(), cf.home.vault.ID, bad, cf.editorRole.ID, actor, "", ""); !errors.Is(err, domain.ErrValidation) {
			t.Fatalf("member key %q must fail validation, got %v", bad, err)
		}
	}
	if err := cf.home.svc.AddFederatedMember(context.Background(), cf.home.vault.ID, "bob@https://follower.example", uuid.New(), actor, "", ""); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("foreign role id must fail validation")
	}
	if err := cf.home.svc.AddFederatedMember(context.Background(), cf.home.vault.ID, "bob@https://follower.example", cf.editorRole.ID, actor, "", ""); err != nil {
		t.Fatalf("valid add: %v", err)
	}
	if !containsAction(cf.home.audit.actions(), domain.ActionMemberAdd) {
		t.Fatalf("federated member add not audited")
	}

	if err := cf.home.svc.RemoveFederatedMember(context.Background(), cf.home.vault.ID, "bob@https://follower.example", actor, "", ""); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if !containsAction(cf.home.audit.actions(), domain.ActionMemberRemove) {
		t.Fatalf("federated member remove not audited")
	}
}

// ---- relay integration -------------------------------------------------------------------

func TestRelay_ControlStateFlowsAndAcks(t *testing.T) {
	cf := newControlFixture(t)
	vaultID := cf.federate(t)

	// Author state at home before the link comes up.
	if _, _, _, err := cf.home.svc.RebuildControlState(context.Background(), cf.home.vault.ID); err != nil {
		t.Fatal(err)
	}

	homeSide := newRelaySide(t)
	followerSide := newRelaySide(t)
	homeSide.links.deps.ControlCurrent = cf.home.svc.CurrentControlState
	homeSide.links.deps.ControlAcked = cf.home.svc.RecordControlAck
	followerSide.links.deps.ControlApply = cf.follower.svc.ApplyControlState

	homeConn, followerConn := newPipePair()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	homeSess := homeSide.links.NewSession(ctx, homeConn, cf.home.vault.ID, "https://follower.example", "home")
	followerSess := followerSide.links.NewSession(ctx, followerConn, vaultID, "https://home.example", "follower")
	go func() { _ = homeSess.Run() }()
	go func() { _ = followerSess.Run() }()

	// The opening push must land the document on the follower and the ack
	// back at home.
	waitFor(t, "replicated control state on follower", func() bool {
		seq, _, err := cf.followerRepl.Get(context.Background(), vaultID)
		return err == nil && seq == 1
	})
	waitFor(t, "control ack at home", func() bool {
		cf.acks.mu.Lock()
		defer cf.acks.mu.Unlock()
		return cf.acks.last[cf.home.vault.ID.String()+"|https://follower.example"] == 1
	})
}
