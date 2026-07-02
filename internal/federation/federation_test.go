package federation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/vaults"
)

// ---- fakes -------------------------------------------------------------------

type fakeKeyStore struct {
	pub, priv []byte
	inserts   int
}

func (f *fakeKeyStore) Get(context.Context) ([]byte, []byte, error) {
	if f.pub == nil {
		return nil, nil, domain.ErrNotFound
	}
	return f.pub, f.priv, nil
}

func (f *fakeKeyStore) Insert(_ context.Context, pub, priv []byte) error {
	f.inserts++
	if f.pub == nil { // first insert wins, mirroring ON CONFLICT DO NOTHING
		f.pub, f.priv = pub, priv
	}
	return nil
}

type fakeFedRepo struct {
	rows map[uuid.UUID]domain.Federation
}

func newFakeFedRepo() *fakeFedRepo { return &fakeFedRepo{rows: map[uuid.UUID]domain.Federation{}} }

func (f *fakeFedRepo) Insert(_ context.Context, fed domain.Federation) (domain.Federation, error) {
	if fed.ID == uuid.Nil {
		fed.ID = uuid.New()
	}
	for _, existing := range f.rows {
		if existing.VaultID == fed.VaultID && existing.PeerURL == fed.PeerURL {
			return domain.Federation{}, domain.ErrConflict
		}
	}
	f.rows[fed.ID] = fed
	return fed, nil
}

func (f *fakeFedRepo) Get(_ context.Context, id uuid.UUID) (domain.Federation, error) {
	fed, ok := f.rows[id]
	if !ok {
		return domain.Federation{}, domain.ErrNotFound
	}
	return fed, nil
}

func (f *fakeFedRepo) ListForVault(_ context.Context, vaultID uuid.UUID) ([]domain.Federation, error) {
	var out []domain.Federation
	for _, fed := range f.rows {
		if fed.VaultID == vaultID {
			out = append(out, fed)
		}
	}
	return out, nil
}

func (f *fakeFedRepo) ListActiveByRole(_ context.Context, role string) ([]domain.Federation, error) {
	var out []domain.Federation
	for _, fed := range f.rows {
		if fed.Role == role && fed.Status == "active" {
			out = append(out, fed)
		}
	}
	return out, nil
}

func (f *fakeFedRepo) GetActiveByVaultAndPeer(_ context.Context, vaultID uuid.UUID, peerURL string) (domain.Federation, error) {
	for _, fed := range f.rows {
		if fed.VaultID == vaultID && fed.PeerURL == peerURL && fed.Status == "active" {
			return fed, nil
		}
	}
	return domain.Federation{}, domain.ErrNotFound
}

func (f *fakeFedRepo) UpdateStatus(_ context.Context, id uuid.UUID, status string, at time.Time) error {
	fed, ok := f.rows[id]
	if !ok {
		return domain.ErrNotFound
	}
	fed.Status = status
	fed.RevokedAt = &at
	f.rows[id] = fed
	return nil
}

type fakeInviteRepo struct {
	rows map[string]domain.FederationInvite
}

func newFakeInviteRepo() *fakeInviteRepo {
	return &fakeInviteRepo{rows: map[string]domain.FederationInvite{}}
}

func (f *fakeInviteRepo) Create(_ context.Context, inv domain.FederationInvite) error {
	f.rows[inv.Token] = inv
	return nil
}

func (f *fakeInviteRepo) Get(_ context.Context, token string) (domain.FederationInvite, error) {
	inv, ok := f.rows[token]
	if !ok {
		return domain.FederationInvite{}, domain.ErrNotFound
	}
	return inv, nil
}

func (f *fakeInviteRepo) MarkUsed(_ context.Context, token string, at time.Time) error {
	inv, ok := f.rows[token]
	if !ok || inv.UsedAt != nil {
		return domain.ErrConflict
	}
	inv.UsedAt = &at
	f.rows[token] = inv
	return nil
}

func (f *fakeInviteRepo) Revoke(_ context.Context, token string, at time.Time) error {
	inv, ok := f.rows[token]
	if !ok {
		return domain.ErrNotFound
	}
	inv.RevokedAt = &at
	f.rows[token] = inv
	return nil
}

func (f *fakeInviteRepo) ListForVault(_ context.Context, vaultID uuid.UUID) ([]domain.FederationInvite, error) {
	var out []domain.FederationInvite
	for _, inv := range f.rows {
		if inv.VaultID == vaultID {
			out = append(out, inv)
		}
	}
	return out, nil
}

type fakeVaultLookup struct {
	rows map[uuid.UUID]domain.Vault
}

func (f *fakeVaultLookup) GetByID(_ context.Context, id uuid.UUID) (domain.Vault, error) {
	v, ok := f.rows[id]
	if !ok {
		return domain.Vault{}, domain.ErrNotFound
	}
	return v, nil
}

type fakeCreator struct {
	created []vaults.CreateInput
}

func (f *fakeCreator) Create(_ context.Context, in vaults.CreateInput) (domain.Vault, error) {
	f.created = append(f.created, in)
	return domain.Vault{ID: in.ID, Slug: in.Slug, Name: in.Name, OwnerUserID: in.CreatedBy}, nil
}

type fakeHome struct {
	identity Identity
	accept   func(AcceptRequest) (AcceptResponse, error)
}

func (f *fakeHome) Identity(context.Context, string) (Identity, error) { return f.identity, nil }
func (f *fakeHome) Accept(_ context.Context, _ string, req AcceptRequest) (AcceptResponse, error) {
	return f.accept(req)
}
func (f *fakeHome) SyncChallenge(context.Context, string, uuid.UUID, string) (string, error) {
	return "", errors.New("not implemented in fake")
}

// ---- harness -----------------------------------------------------------------

type fedFixture struct {
	svc     *Service
	keys    *fakeKeyStore
	feds    *fakeFedRepo
	invites *fakeInviteRepo
	vaults  *fakeVaultLookup
	creator *fakeCreator
	vault   domain.Vault
}

func newFedFixture(t *testing.T, baseURL string) *fedFixture {
	t.Helper()
	fx := &fedFixture{
		keys:    &fakeKeyStore{},
		feds:    newFakeFedRepo(),
		invites: newFakeInviteRepo(),
		creator: &fakeCreator{},
	}
	fx.vault = domain.Vault{ID: uuid.New(), Slug: "team", Name: "Team", OwnerUserID: uuid.New()}
	fx.vaults = &fakeVaultLookup{rows: map[uuid.UUID]domain.Vault{fx.vault.ID: fx.vault}}

	svc, err := NewService(context.Background(), Deps{
		Keys:        fx.keys,
		Federations: fx.feds,
		Invites:     fx.invites,
		Vaults:      fx.vaults,
		Creator:     fx.creator,
		BaseURL:     baseURL,
	})
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	fx.svc = svc
	return fx
}

func (fx *fedFixture) mintInvite(t *testing.T, hint string) domain.FederationInvite {
	t.Helper()
	inv, err := fx.svc.CreateInvite(context.Background(), CreateInviteInput{
		VaultID:       fx.vault.ID,
		Actor:         fx.vault.OwnerUserID,
		ServerURLHint: hint,
	})
	if err != nil {
		t.Fatalf("CreateInvite: %v", err)
	}
	return inv
}

func signedAccept(t *testing.T, token, followerURL string) (AcceptRequest, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, AcceptMessage(token, followerURL))
	return AcceptRequest{
		Token:          token,
		FollowerURL:    followerURL,
		FollowerPubKey: hex.EncodeToString(pub),
		Signature:      hex.EncodeToString(sig),
	}, pub
}

// ---- keys ----------------------------------------------------------------------

func TestLoadOrCreateKeys_MintsOnceThenReuses(t *testing.T) {
	store := &fakeKeyStore{}
	pub1, _, err := loadOrCreateKeys(context.Background(), store)
	if err != nil {
		t.Fatalf("first boot: %v", err)
	}
	pub2, _, err := loadOrCreateKeys(context.Background(), store)
	if err != nil {
		t.Fatalf("second boot: %v", err)
	}
	if !pub1.Equal(pub2) {
		t.Fatalf("keypair changed across boots")
	}
	if store.inserts != 1 {
		t.Fatalf("inserts = %d, want 1", store.inserts)
	}
}

// ---- identity / invites ----------------------------------------------------------

func TestIdentity_RequiresBaseURL(t *testing.T) {
	fx := newFedFixture(t, "")
	if _, err := fx.svc.Identity(); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("want ErrValidation without base URL, got %v", err)
	}
	if _, err := fx.svc.CreateInvite(context.Background(), CreateInviteInput{VaultID: fx.vault.ID}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("invite creation must also require base URL, got %v", err)
	}
}

func TestCreateInvite_DefaultsAndAudits(t *testing.T) {
	fx := newFedFixture(t, "https://home.example")
	inv := fx.mintInvite(t, "")
	if len(inv.Token) != 64 {
		t.Fatalf("token length = %d, want 64 hex chars", len(inv.Token))
	}
	if !inv.ExpiresAt.After(time.Now()) {
		t.Fatalf("default expiry not in the future")
	}
}

// ---- accept ----------------------------------------------------------------------

func TestAccept_HappyPath(t *testing.T) {
	fx := newFedFixture(t, "https://home.example")
	inv := fx.mintInvite(t, "")
	req, pub := signedAccept(t, inv.Token, "https://follower.example")

	resp, err := fx.svc.Accept(context.Background(), req)
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	if resp.Vault.ID != fx.vault.ID || resp.Vault.Slug != "team" {
		t.Fatalf("wrong vault in response: %+v", resp.Vault)
	}
	if resp.Home.URL != "https://home.example" {
		t.Fatalf("home identity url = %q", resp.Home.URL)
	}
	feds, _ := fx.feds.ListForVault(context.Background(), fx.vault.ID)
	if len(feds) != 1 || feds[0].Role != "home" || feds[0].PeerURL != "https://follower.example" {
		t.Fatalf("federation row wrong: %+v", feds)
	}
	if !ed25519.PublicKey(feds[0].PeerPubKey).Equal(pub) {
		t.Fatalf("stored peer key mismatch")
	}
	// Single use: the same token must not work twice.
	req2, _ := signedAccept(t, inv.Token, "https://other.example")
	if _, err := fx.svc.Accept(context.Background(), req2); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("second accept must fail forbidden, got %v", err)
	}
}

func TestAccept_RejectsBadSignature(t *testing.T) {
	fx := newFedFixture(t, "https://home.example")
	inv := fx.mintInvite(t, "")
	req, _ := signedAccept(t, inv.Token, "https://follower.example")
	// Signature over a different message: swap the URL after signing.
	req.FollowerURL = "https://evil.example"

	if _, err := fx.svc.Accept(context.Background(), req); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("want forbidden on bad signature, got %v", err)
	}
}

func TestAccept_RejectsExpiredRevokedUnknown(t *testing.T) {
	fx := newFedFixture(t, "https://home.example")

	expired := fx.mintInvite(t, "")
	row := fx.invites.rows[expired.Token]
	row.ExpiresAt = time.Now().Add(-time.Hour)
	fx.invites.rows[expired.Token] = row

	revoked := fx.mintInvite(t, "")
	_ = fx.invites.Revoke(context.Background(), revoked.Token, time.Now())

	for name, token := range map[string]string{
		"expired": expired.Token,
		"revoked": revoked.Token,
		"unknown": newToken(),
	} {
		req, _ := signedAccept(t, token, "https://follower.example")
		if _, err := fx.svc.Accept(context.Background(), req); !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("%s: want forbidden, got %v", name, err)
		}
	}
}

func TestAccept_EnforcesServerURLHint(t *testing.T) {
	fx := newFedFixture(t, "https://home.example")
	inv := fx.mintInvite(t, "https://expected.example")

	req, _ := signedAccept(t, inv.Token, "https://someone-else.example")
	if _, err := fx.svc.Accept(context.Background(), req); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("hint mismatch must be forbidden, got %v", err)
	}

	req2, _ := signedAccept(t, inv.Token, "https://expected.example")
	if _, err := fx.svc.Accept(context.Background(), req2); err != nil {
		t.Fatalf("hinted follower must be accepted: %v", err)
	}
}

func TestAccept_RejectsSelfFederation(t *testing.T) {
	fx := newFedFixture(t, "https://home.example")
	inv := fx.mintInvite(t, "")
	req, _ := signedAccept(t, inv.Token, "https://home.example")
	if _, err := fx.svc.Accept(context.Background(), req); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("self-federation must be rejected, got %v", err)
	}
}

// ---- join ------------------------------------------------------------------------

func TestJoin_ProvisionsReplicaAndFollowerRow(t *testing.T) {
	// Home side: a real service so the handshake is verified end-to-end.
	home := newFedFixture(t, "https://home.example")
	inv := home.mintInvite(t, "")
	homeIdent, _ := home.svc.Identity()

	follower := newFedFixture(t, "https://follower.example")
	follower.svc.client = &fakeHome{
		identity: homeIdent,
		accept: func(req AcceptRequest) (AcceptResponse, error) {
			return home.svc.Accept(context.Background(), req)
		},
	}

	actor := uuid.New()
	replica, fed, err := follower.svc.Join(context.Background(), JoinInput{
		HomeURL: "https://home.example",
		Token:   inv.Token,
		Actor:   actor,
	})
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	if replica.ID != home.vault.ID {
		t.Fatalf("replica must reuse home's vault id: %v vs %v", replica.ID, home.vault.ID)
	}
	if len(follower.creator.created) != 1 || follower.creator.created[0].Slug != "team" {
		t.Fatalf("replica vault not provisioned from home metadata: %+v", follower.creator.created)
	}
	if fed.Role != "follower" || fed.PeerURL != "https://home.example" || fed.Status != "active" {
		t.Fatalf("follower federation row wrong: %+v", fed)
	}
	// And home recorded the mirror row.
	homeFeds, _ := home.feds.ListForVault(context.Background(), home.vault.ID)
	if len(homeFeds) != 1 || homeFeds[0].PeerURL != "https://follower.example" {
		t.Fatalf("home row missing: %+v", homeFeds)
	}
}

func TestJoin_RequiresBaseURLAndValidHome(t *testing.T) {
	fx := newFedFixture(t, "")
	if _, _, err := fx.svc.Join(context.Background(), JoinInput{HomeURL: "https://home.example", Token: "t"}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("join without base URL must fail validation, got %v", err)
	}

	fx2 := newFedFixture(t, "https://follower.example")
	if _, _, err := fx2.svc.Join(context.Background(), JoinInput{HomeURL: "not a url", Token: "t"}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("join with bad home URL must fail validation, got %v", err)
	}
	if _, _, err := fx2.svc.Join(context.Background(), JoinInput{HomeURL: "https://follower.example", Token: "t"}); !errors.Is(err, domain.ErrValidation) {
		t.Fatalf("join with self URL must fail validation, got %v", err)
	}
}

// ---- revoke ------------------------------------------------------------------------

func TestRevokeFederation(t *testing.T) {
	fx := newFedFixture(t, "https://home.example")
	inv := fx.mintInvite(t, "")
	req, _ := signedAccept(t, inv.Token, "https://follower.example")
	if _, err := fx.svc.Accept(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	feds, _ := fx.feds.ListForVault(context.Background(), fx.vault.ID)

	if err := fx.svc.RevokeFederation(context.Background(), fx.vault.ID, feds[0].ID, fx.vault.OwnerUserID, "", ""); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	got, _ := fx.feds.Get(context.Background(), feds[0].ID)
	if got.Status != "revoked" || got.RevokedAt == nil {
		t.Fatalf("federation not revoked: %+v", got)
	}
	// Idempotence guard: revoking again conflicts.
	if err := fx.svc.RevokeFederation(context.Background(), fx.vault.ID, feds[0].ID, fx.vault.OwnerUserID, "", ""); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("second revoke must conflict, got %v", err)
	}
}
