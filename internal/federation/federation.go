// Package federation implements v3 Phase F1: server identity (Ed25519
// keypair), federation invites, and the home↔follower handshake that binds a
// vault to a peer server. Content-plane relay is F2; the signed control
// plane is F3. See SPEC-V3.md "Federation".
package federation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/audit"
	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/vaults"
)

// acceptMessagePrefix versions the signed handshake payload. The follower
// signs prefix|token|follower_url with its private key; home verifies with
// the public key presented in the same request. The signature proves the
// accepting party controls the private key it is enrolling — the invite
// token (high-entropy, single-use, out-of-band) is what proves authorisation.
const acceptMessagePrefix = "lumi-federation-accept-v1"

// InviteTTLDefault bounds how long a federation invite stays usable.
const InviteTTLDefault = 7 * 24 * time.Hour

// AcceptMessage builds the canonical byte string both sides sign/verify.
func AcceptMessage(token, followerURL string) []byte {
	return []byte(acceptMessagePrefix + "|" + token + "|" + followerURL)
}

// ---- storage boundaries ------------------------------------------------------

type KeyStore interface {
	Get(ctx context.Context) (pub, priv []byte, err error)
	Insert(ctx context.Context, pub, priv []byte) error
}

type FederationRepo interface {
	Insert(ctx context.Context, f domain.Federation) (domain.Federation, error)
	Get(ctx context.Context, id uuid.UUID) (domain.Federation, error)
	ListForVault(ctx context.Context, vaultID uuid.UUID) ([]domain.Federation, error)
	ListActiveByRole(ctx context.Context, role string) ([]domain.Federation, error)
	GetActiveByVaultAndPeer(ctx context.Context, vaultID uuid.UUID, peerURL string) (domain.Federation, error)
	UpdateStatus(ctx context.Context, id uuid.UUID, status string, at time.Time) error
}

type InviteRepo interface {
	Create(ctx context.Context, inv domain.FederationInvite) error
	Get(ctx context.Context, token string) (domain.FederationInvite, error)
	MarkUsed(ctx context.Context, token string, at time.Time) error
	Revoke(ctx context.Context, token string, at time.Time) error
	ListForVault(ctx context.Context, vaultID uuid.UUID) ([]domain.FederationInvite, error)
}

type VaultLookup interface {
	GetByID(ctx context.Context, id uuid.UUID) (domain.Vault, error)
}

// VaultCreator provisions the local replica vault when this server joins a
// federation as follower. Implemented by *vaults.Service.
type VaultCreator interface {
	Create(ctx context.Context, in vaults.CreateInput) (domain.Vault, error)
}

// HomeClient talks to the home server during join and relay setup.
// Implemented by httpClient; faked in tests.
type HomeClient interface {
	Identity(ctx context.Context, homeURL string) (Identity, error)
	Accept(ctx context.Context, homeURL string, req AcceptRequest) (AcceptResponse, error)
	SyncChallenge(ctx context.Context, homeURL string, vaultID uuid.UUID, peerURL string) (nonce string, err error)
}

// ---- wire shapes (shared by handlers and client) ------------------------------

// Identity is the public identity of a server.
type Identity struct {
	URL       string `json:"url"`
	PublicKey string `json:"public_key"` // hex-encoded Ed25519 public key
}

// AcceptRequest is the server-to-server accept payload.
type AcceptRequest struct {
	Token           string `json:"token"`
	FollowerURL     string `json:"follower_url"`
	FollowerPubKey  string `json:"follower_pubkey"` // hex
	Signature       string `json:"signature"`       // hex, over AcceptMessage
	JurisdictionOpt string `json:"jurisdiction,omitempty"`
}

// AcceptResponse is home's answer: the vault being federated + home identity.
type AcceptResponse struct {
	Vault VaultInfo `json:"vault"`
	Home  Identity  `json:"home"`
}

type VaultInfo struct {
	ID   uuid.UUID `json:"id"`
	Slug string    `json:"slug"`
	Name string    `json:"name"`
}

// ---- service -------------------------------------------------------------------

type Service struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey

	federations FederationRepo
	invites     InviteRepo
	vaults      VaultLookup
	creator     VaultCreator
	client      HomeClient
	audit       audit.Recorder
	baseURL     string
	relay       LinkController
	now         func() time.Time
}

type Deps struct {
	Keys        KeyStore
	Federations FederationRepo
	Invites     InviteRepo
	Vaults      VaultLookup
	Creator     VaultCreator
	Client      HomeClient // nil → default HTTP client
	Audit       audit.Recorder
	BaseURL     string // LUMI_PUBLIC_BASE_URL; empty disables federation endpoints
}

// NewService loads (or mints, on first boot) the server keypair and wires the
// federation service.
func NewService(ctx context.Context, d Deps) (*Service, error) {
	if d.Keys == nil || d.Federations == nil || d.Invites == nil || d.Vaults == nil {
		return nil, errors.New("federation.NewService: missing dependency")
	}
	if d.Audit == nil {
		d.Audit = audit.Noop{}
	}
	pub, priv, err := loadOrCreateKeys(ctx, d.Keys)
	if err != nil {
		return nil, err
	}
	svc := &Service{
		pub:         pub,
		priv:        priv,
		federations: d.Federations,
		invites:     d.Invites,
		vaults:      d.Vaults,
		creator:     d.Creator,
		client:      d.Client,
		audit:       d.Audit,
		baseURL:     strings.TrimRight(d.BaseURL, "/"),
		now:         time.Now,
	}
	if svc.client == nil {
		svc.client = newHTTPClient()
	}
	return svc, nil
}

func loadOrCreateKeys(ctx context.Context, store KeyStore) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := store.Get(ctx)
	if err == nil {
		if len(pub) != ed25519.PublicKeySize || len(priv) != ed25519.PrivateKeySize {
			return nil, nil, fmt.Errorf("federation: stored keypair has invalid size (%d/%d)", len(pub), len(priv))
		}
		return ed25519.PublicKey(pub), ed25519.PrivateKey(priv), nil
	}
	if !errors.Is(err, domain.ErrNotFound) {
		return nil, nil, err
	}
	newPub, newPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("federation: generate keypair: %w", err)
	}
	if err := store.Insert(ctx, newPub, newPriv); err != nil {
		return nil, nil, err
	}
	// Re-read: a concurrent first boot may have won the id=1 insert race;
	// both replicas must end up using the same key.
	pub, priv, err = store.Get(ctx)
	if err != nil {
		return nil, nil, err
	}
	return ed25519.PublicKey(pub), ed25519.PrivateKey(priv), nil
}

// Identity returns this server's public identity. Requires BaseURL.
func (s *Service) Identity() (Identity, error) {
	if s.baseURL == "" {
		return Identity{}, fmt.Errorf("%w: LUMI_PUBLIC_BASE_URL must be set for federation", domain.ErrValidation)
	}
	return Identity{URL: s.baseURL, PublicKey: hex.EncodeToString(s.pub)}, nil
}

// ---- invites (home side) -------------------------------------------------------

type CreateInviteInput struct {
	VaultID       uuid.UUID
	Actor         uuid.UUID
	ServerURLHint string
	ExpiresAt     time.Time
	IP, UserAgent string
}

func (s *Service) CreateInvite(ctx context.Context, in CreateInviteInput) (domain.FederationInvite, error) {
	if s.baseURL == "" {
		return domain.FederationInvite{}, fmt.Errorf("%w: LUMI_PUBLIC_BASE_URL must be set for federation", domain.ErrValidation)
	}
	if in.ServerURLHint != "" {
		if err := validateServerURL(in.ServerURLHint); err != nil {
			return domain.FederationInvite{}, err
		}
	}
	if _, err := s.vaults.GetByID(ctx, in.VaultID); err != nil {
		return domain.FederationInvite{}, err
	}
	expires := in.ExpiresAt
	if expires.IsZero() {
		expires = s.now().Add(InviteTTLDefault)
	}
	if !expires.After(s.now()) {
		return domain.FederationInvite{}, fmt.Errorf("%w: expires_at must be in the future", domain.ErrValidation)
	}
	inv := domain.FederationInvite{
		Token:         newToken(),
		VaultID:       in.VaultID,
		InviterUserID: in.Actor,
		ServerURLHint: normalizeServerURL(in.ServerURLHint),
		ExpiresAt:     expires.UTC(),
		CreatedAt:     s.now().UTC(),
	}
	if err := s.invites.Create(ctx, inv); err != nil {
		return domain.FederationInvite{}, err
	}
	s.recordAudit(ctx, &in.Actor, in.VaultID, domain.ActionFederationInvite, in.IP, in.UserAgent, map[string]any{
		"vault_id":        in.VaultID,
		"server_url_hint": inv.ServerURLHint,
		"expires_at":      inv.ExpiresAt,
	})
	return inv, nil
}

func (s *Service) ListInvites(ctx context.Context, vaultID uuid.UUID) ([]domain.FederationInvite, error) {
	return s.invites.ListForVault(ctx, vaultID)
}

func (s *Service) RevokeInvite(ctx context.Context, vaultID uuid.UUID, token string, actor uuid.UUID, ip, ua string) error {
	inv, err := s.invites.Get(ctx, token)
	if err != nil {
		return err
	}
	if inv.VaultID != vaultID {
		return domain.ErrNotFound
	}
	if err := s.invites.Revoke(ctx, token, s.now().UTC()); err != nil {
		return err
	}
	s.recordAudit(ctx, &actor, vaultID, domain.ActionFederationRevoke, ip, ua, map[string]any{
		"kind":     "invite",
		"vault_id": vaultID,
	})
	return nil
}

// ---- accept (home side, server-to-server) --------------------------------------

// Accept validates a follower's signed handshake and records the federation.
// Unauthenticated by design: the single-use high-entropy token authorises,
// the Ed25519 signature binds the enrolled key to the request.
func (s *Service) Accept(ctx context.Context, req AcceptRequest) (AcceptResponse, error) {
	ident, err := s.Identity()
	if err != nil {
		return AcceptResponse{}, err
	}
	followerURL := normalizeServerURL(req.FollowerURL)
	if err := validateServerURL(followerURL); err != nil {
		return AcceptResponse{}, err
	}
	if followerURL == s.baseURL {
		return AcceptResponse{}, fmt.Errorf("%w: a server cannot federate with itself", domain.ErrValidation)
	}
	pubKey, err := hex.DecodeString(req.FollowerPubKey)
	if err != nil || len(pubKey) != ed25519.PublicKeySize {
		return AcceptResponse{}, fmt.Errorf("%w: follower_pubkey must be a hex Ed25519 public key", domain.ErrValidation)
	}
	sig, err := hex.DecodeString(req.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return AcceptResponse{}, fmt.Errorf("%w: signature must be a hex Ed25519 signature", domain.ErrValidation)
	}
	if !ed25519.Verify(ed25519.PublicKey(pubKey), AcceptMessage(req.Token, followerURL), sig) {
		return AcceptResponse{}, fmt.Errorf("%w: signature verification failed", domain.ErrForbidden)
	}

	inv, err := s.invites.Get(ctx, req.Token)
	if err != nil {
		// Uniform failure for unknown tokens: no oracle for token guessing.
		return AcceptResponse{}, fmt.Errorf("%w: invite not usable", domain.ErrForbidden)
	}
	now := s.now()
	switch {
	case inv.RevokedAt != nil, inv.UsedAt != nil, !inv.ExpiresAt.After(now):
		return AcceptResponse{}, fmt.Errorf("%w: invite not usable", domain.ErrForbidden)
	case inv.ServerURLHint != "" && inv.ServerURLHint != followerURL:
		return AcceptResponse{}, fmt.Errorf("%w: invite not usable", domain.ErrForbidden)
	}
	// MarkUsed is atomic (used_at IS NULL guard): concurrent accepts race
	// safely, exactly one wins.
	if err := s.invites.MarkUsed(ctx, req.Token, now.UTC()); err != nil {
		return AcceptResponse{}, fmt.Errorf("%w: invite not usable", domain.ErrForbidden)
	}

	v, err := s.vaults.GetByID(ctx, inv.VaultID)
	if err != nil {
		return AcceptResponse{}, err
	}
	var jurisdiction *string
	if j := strings.TrimSpace(req.JurisdictionOpt); j != "" {
		jurisdiction = &j
	}
	if _, err := s.federations.Insert(ctx, domain.Federation{
		VaultID:      v.ID,
		Role:         "home",
		PeerURL:      followerURL,
		PeerPubKey:   pubKey,
		Jurisdiction: jurisdiction,
		Status:       "active",
		CreatedAt:    now.UTC(),
	}); err != nil {
		return AcceptResponse{}, err
	}

	s.recordAudit(ctx, nil, v.ID, domain.ActionFederationAccept, "", "", map[string]any{
		"role":         "home",
		"peer_url":     followerURL,
		"jurisdiction": req.JurisdictionOpt,
	})
	return AcceptResponse{
		Vault: VaultInfo{ID: v.ID, Slug: v.Slug, Name: v.Name},
		Home:  ident,
	}, nil
}

// ---- join (follower side) -------------------------------------------------------

type JoinInput struct {
	HomeURL       string
	Token         string
	Jurisdiction  string
	Actor         uuid.UUID
	IP, UserAgent string
}

// Join makes this server a follower for a vault homed elsewhere: it performs
// the signed accept handshake against home and provisions a local replica
// vault (same UUID, home's slug, joining user as local Admin — provisional
// until F3 replicates home's control plane). Content sync lands in F2.
func (s *Service) Join(ctx context.Context, in JoinInput) (domain.Vault, domain.Federation, error) {
	if s.creator == nil {
		return domain.Vault{}, domain.Federation{}, errors.New("federation: join deps not wired")
	}
	if _, err := s.Identity(); err != nil {
		return domain.Vault{}, domain.Federation{}, err
	}
	homeURL := normalizeServerURL(in.HomeURL)
	if err := validateServerURL(homeURL); err != nil {
		return domain.Vault{}, domain.Federation{}, err
	}
	if homeURL == s.baseURL {
		return domain.Vault{}, domain.Federation{}, fmt.Errorf("%w: a server cannot federate with itself", domain.ErrValidation)
	}
	if strings.TrimSpace(in.Token) == "" {
		return domain.Vault{}, domain.Federation{}, fmt.Errorf("%w: token is required", domain.ErrValidation)
	}

	homeIdent, err := s.client.Identity(ctx, homeURL)
	if err != nil {
		return domain.Vault{}, domain.Federation{}, fmt.Errorf("federation: home identity: %w", err)
	}
	homePub, err := hex.DecodeString(homeIdent.PublicKey)
	if err != nil || len(homePub) != ed25519.PublicKeySize {
		return domain.Vault{}, domain.Federation{}, fmt.Errorf("%w: home returned an invalid public key", domain.ErrValidation)
	}

	sig := ed25519.Sign(s.priv, AcceptMessage(in.Token, s.baseURL))
	resp, err := s.client.Accept(ctx, homeURL, AcceptRequest{
		Token:           in.Token,
		FollowerURL:     s.baseURL,
		FollowerPubKey:  hex.EncodeToString(s.pub),
		Signature:       hex.EncodeToString(sig),
		JurisdictionOpt: strings.TrimSpace(in.Jurisdiction),
	})
	if err != nil {
		return domain.Vault{}, domain.Federation{}, fmt.Errorf("federation: accept at home: %w", err)
	}

	replica, err := s.creator.Create(ctx, vaults.CreateInput{
		ID:        resp.Vault.ID,
		Name:      resp.Vault.Name,
		Slug:      resp.Vault.Slug,
		CreatedBy: in.Actor,
		IP:        in.IP,
		UserAgent: in.UserAgent,
	})
	if err != nil {
		return domain.Vault{}, domain.Federation{}, fmt.Errorf("federation: provision replica vault: %w", err)
	}

	var jurisdiction *string
	if j := strings.TrimSpace(in.Jurisdiction); j != "" {
		jurisdiction = &j
	}
	fed, err := s.federations.Insert(ctx, domain.Federation{
		VaultID:      replica.ID,
		Role:         "follower",
		PeerURL:      homeURL,
		PeerPubKey:   homePub,
		Jurisdiction: jurisdiction,
		Status:       "active",
		CreatedAt:    s.now().UTC(),
	})
	if err != nil {
		return domain.Vault{}, domain.Federation{}, err
	}

	// Kick the F2 relay so content starts flowing without a restart.
	if s.relay != nil {
		s.relay.StartLink(context.WithoutCancel(ctx), replica.ID, homeURL)
	}

	s.recordAudit(ctx, &in.Actor, replica.ID, domain.ActionFederationAccept, in.IP, in.UserAgent, map[string]any{
		"role":     "follower",
		"peer_url": homeURL,
	})
	return replica, fed, nil
}

// ---- federation links -----------------------------------------------------------

func (s *Service) ListFederations(ctx context.Context, vaultID uuid.UUID) ([]domain.Federation, error) {
	return s.federations.ListForVault(ctx, vaultID)
}

// LinkController is the relay-manager surface the service pokes on
// lifecycle changes: start a follower loop after Join, tear a link down on
// revoke. Wired via SetLinkController; nil-safe.
type LinkController interface {
	StartLink(ctx context.Context, vaultID uuid.UUID, homeURL string)
	StopLink(vaultID uuid.UUID, peerURL string)
}

// SetLinkController wires the F2 relay manager. Called by the composition
// root after both objects exist (they reference each other).
func (s *Service) SetLinkController(lc LinkController) { s.relay = lc }

// RevokeFederation severs a link from this side: the row flips to revoked,
// the live relay session (if any) is closed, and reconnect loops stop.
// Signed revocation events to the peer are F3.
func (s *Service) RevokeFederation(ctx context.Context, vaultID, fedID, actor uuid.UUID, ip, ua string) error {
	f, err := s.federations.Get(ctx, fedID)
	if err != nil {
		return err
	}
	if f.VaultID != vaultID {
		return domain.ErrNotFound
	}
	if f.Status != "active" {
		return fmt.Errorf("%w: federation already %s", domain.ErrConflict, f.Status)
	}
	if err := s.federations.UpdateStatus(ctx, fedID, "revoked", s.now().UTC()); err != nil {
		return err
	}
	if s.relay != nil {
		s.relay.StopLink(vaultID, f.PeerURL)
	}
	s.recordAudit(ctx, &actor, vaultID, domain.ActionFederationRevoke, ip, ua, map[string]any{
		"kind":     "federation",
		"peer_url": f.PeerURL,
	})
	return nil
}

// ---- helpers ---------------------------------------------------------------------

func newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func normalizeServerURL(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), "/")
}

func validateServerURL(raw string) error {
	u, err := url.ParseRequestURI(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%w: server url must be an absolute http(s) URL", domain.ErrValidation)
	}
	return nil
}

func (s *Service) recordAudit(ctx context.Context, userID *uuid.UUID, vaultID uuid.UUID, action, ip, ua string, payload map[string]any) {
	entry := domain.AuditEntry{Action: action, CreatedAt: s.now()}
	if userID != nil && *userID != uuid.Nil {
		entry.UserID = userID
	}
	if vaultID != uuid.Nil {
		vid := vaultID
		entry.VaultID = &vid
	}
	if ip != "" {
		entry.IP = &ip
	}
	if ua != "" {
		entry.UserAgent = &ua
	}
	if b, err := marshalPayload(payload); err == nil {
		entry.Payload = b
	}
	_ = s.audit.Record(ctx, entry)
}
