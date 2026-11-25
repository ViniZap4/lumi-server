// Package domain holds canonical types shared across the server. Types are
// pure data: no behaviour, no I/O. Service packages embed or wrap these.
package domain

import (
	"time"

	"github.com/google/uuid"
)

// User represents a server-scoped account. Identity is independent per server
// (no central identity provider). See SPEC.md "Identity".
//
// DisabledAt, FailedLogins and LockedUntil are operator-managed account
// state (docs/ADMIN.md): a disabled account cannot log in or use any
// session; a locked one refuses logins until LockedUntil.
type User struct {
	ID           uuid.UUID
	Username     string
	PasswordHash string
	DisplayName  string
	CreatedAt    time.Time
	DisabledAt   *time.Time
	FailedLogins int
	LockedUntil  *time.Time
	// ServerAdmin lets the account sign in to the admin panel with its
	// password (migration 0009, SPEC-PARTE2 §10).
	ServerAdmin bool
}

// Session is a bearer credential issued at login. Validated via constant-time
// compare. Treat as a password; never log raw tokens.
type Session struct {
	Token      string
	UserID     uuid.UUID
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastUsedAt time.Time
}

// Vault is the unit of organisation. May be local-only on disk or
// server-bound. Server-side rows exist only for server-bound vaults.
//
// OwnerUserID is the single owner (v3 Phase O): always holds an
// Admin-equivalent grant that members.manage cannot revoke; transferable via
// the transfer-ownership endpoint. CreatedBy is historical provenance and is
// nullified (uuid.Nil) when the creator exercises LGPD erasure after
// transferring ownership away. CopiedFrom is non-nil JSON provenance when the
// vault was created by share-a-copy.
type Vault struct {
	ID          uuid.UUID
	Slug        string
	Name        string
	CreatedBy   uuid.UUID
	OwnerUserID uuid.UUID
	CopiedFrom  []byte
	CreatedAt   time.Time
}

// Role is a named capability set scoped to a single vault. Seed roles
// (Admin/Editor/Viewer/Commenter) are protected by IsSeed = true.
type Role struct {
	ID           uuid.UUID
	VaultID      uuid.UUID
	Name         string
	Capabilities CapabilitySet
	IsSeed       bool
	// MirrorReadOnly marks a role clamped to read-only because the vault
	// is a mirror on this server: denials answer "mirror_read_only".
	MirrorReadOnly bool
}

// MirrorCapabilities is everything a role may keep on a mirror vault.
var MirrorCapabilities = CapabilitySet{CapNoteRead, CapVaultExport}

// ClampToMirror intersects the role with MirrorCapabilities.
func (r Role) ClampToMirror() Role {
	clamped := CapabilitySet{}
	for _, c := range MirrorCapabilities {
		if r.Capabilities.Has(c) {
			clamped = append(clamped, c)
		}
	}
	r.Capabilities = clamped
	r.MirrorReadOnly = true
	return r
}

// Member is a (user, vault, role) triple.
type Member struct {
	VaultID  uuid.UUID
	UserID   uuid.UUID
	RoleID   uuid.UUID
	JoinedAt time.Time
}

// Invite is a one-shot or limited-use registration/join token.
type Invite struct {
	Token         string
	VaultID       uuid.UUID
	InviterUserID uuid.UUID
	RoleID        uuid.UUID
	EmailHint     string
	MaxUses       int
	UseCount      int
	ExpiresAt     time.Time
	CreatedAt     time.Time
	RevokedAt     *time.Time
}

// Note is metadata for a markdown file inside a vault. ID is the filename
// stem; uniqueness is per-vault (composite PK with VaultID).
//
// ChangeSeq is the vault seq of the note's last change on this server
// (SPEC-LIVROS §3.4); stamped by the store, ignored on input.
//
// CRDTEpoch identifies the note's CRDT history ("lineage", see
// docs/CRDT-CLIENT-PROTOCOL.md §12). It is opaque and changes whenever a
// new history starts for the id: creation, delete+recreate, seeding from
// the file. Edits, FS diff merges, compaction and moves keep it. On
// insert an empty value is replaced by a fresh epoch; on update the
// stored value is kept (only the CRDT registry rotates it).
type Note struct {
	ID        string
	VaultID   uuid.UUID
	Path      string
	Title     string
	CreatedAt time.Time
	UpdatedAt time.Time
	ChangeSeq int64
	CRDTEpoch string
}

// NoteTombstone records a deleted note id at the vault seq of the delete.
type NoteTombstone struct {
	ID  string
	Seq int64
}

// NoteChanges is one page of a vault's change log: notes whose ChangeSeq
// and tombstones whose Seq lie in (after, head], merged in seq order.
// More reports that the page was cut at the limit; the caller continues
// from the highest seq it received.
type NoteChanges struct {
	Notes   []Note
	Deleted []NoteTombstone
	Head    int64
	More    bool
}

// Consent records a user's acceptance of a specific ToS+Privacy version pair.
// Immutable: every acceptance is a new row.
type Consent struct {
	ID             int64
	UserID         uuid.UUID
	TosVersion     string
	PrivacyVersion string
	AcceptedAt     time.Time
	IP             *string
	UserAgent      *string
}

// AuditEntry is recorded for every sensitive action. PII fields are nullable
// because user erasure nullifies them (rows retained for audit integrity).
type AuditEntry struct {
	ID        int64
	UserID    *uuid.UUID
	VaultID   *uuid.UUID
	Action    string
	Payload   []byte
	IP        *string
	UserAgent *string
	CreatedAt time.Time
}

// AuditAction values. Keep in sync with SPEC.md vocabulary.
const (
	ActionAuthLogin       = "auth.login"
	ActionAuthLoginFailed = "auth.login_failed"
	// ActionAdminLoginFailed is a refused admin-panel password login
	// (POST /admin/v1/session); same payload as auth.login_failed.
	ActionAdminLoginFailed   = "admin.login_failed"
	ActionAuthLogout         = "auth.logout"
	ActionAuthRegister       = "auth.register"
	ActionAuthPasswordChange = "auth.password_change"
	ActionUserUpdate         = "user.update"
	ActionUserDelete         = "user.delete"
	ActionUserExportRequest  = "user.export_request"
	ActionVaultCreate        = "vault.create"
	ActionVaultDelete        = "vault.delete"
	ActionVaultUpdate        = "vault.update"
	ActionVaultTransfer      = "vault.transfer"
	ActionVaultCopy          = "vault.copy"
	ActionMemberInvite       = "member.invite"
	ActionMemberAdd          = "member.add"
	ActionMemberRemove       = "member.remove"
	ActionMemberRoleChange   = "member.role_change"
	ActionRoleCreate         = "role.create"
	ActionRoleUpdate         = "role.update"
	ActionRoleDelete         = "role.delete"
	ActionInviteCreate       = "invite.create"
	ActionInviteAccept       = "invite.accept"
	ActionInviteRevoke       = "invite.revoke"
	ActionConsentAccept      = "consent.accept"
	ActionConsentUpdate      = "consent.update"
	ActionNoteCreate         = "note.create"
	ActionNoteEdit           = "note.edit"
	ActionNoteMove           = "note.move"
	ActionNoteDelete         = "note.delete"
	ActionFederationInvite   = "federation.invite"
	ActionFederationAccept   = "federation.accept"
	ActionFederationRevoke   = "federation.revoke"
	// ActionFederationPeerDenied: home refused a write a follower relayed
	// (the link's users lack the capability in home's control state).
	ActionFederationPeerDenied = "federation.peer_denied"
	// One-way mirrors (docs/SPEC-ESPELHO-SELADO.md part A).
	ActionFederationMirrorViolation = "federation.mirror_violation" // home: a mirror sent content
	ActionMirrorLocalWriteBlocked   = "mirror.local_write_blocked"  // mirror: a local write was refused
	ActionMirrorPromote             = "mirror.promote"
	ActionMirrorPurged              = "mirror.purged"
	// M2/M3 (docs/SPEC-ESPELHO-SELADO.md §A8, §A9, §A15).
	ActionFederationMirrorDivergent = "federation.mirror_divergent" // home: a mirror's copy is not dominated by home's
	ActionFederationErasureLagging  = "federation.erasure_lagging"  // home: a mirror has not applied deletes within the SLA
	ActionFederationUnlinked        = "federation.unlinked"         // home: the mirror's operator unlinked
	ActionMirrorIntegrity           = "mirror.integrity"            // mirror: an integrity pass rewrote files
	ActionPublishEnable             = "publish.enable"
	ActionPublishDisable            = "publish.disable"
)

// Federation binds a vault to a peer server (v3 F1). On the home server the
// row points at a follower; on a follower it points at home. Content/control
// replication over this link lands in F2/F3.
type Federation struct {
	ID           uuid.UUID
	VaultID      uuid.UUID
	Role         string // "home" | "follower" — this server's role for the vault
	PeerURL      string
	PeerPubKey   []byte // Ed25519 public key of the peer
	Jurisdiction *string
	Status       string // "active" | "revoked" | "severed"
	LastAckedSeq int64  // home side: follower's confirmed control-state cursor
	CreatedAt    time.Time
	RevokedAt    *time.Time

	// Mode is "replica" (bidirectional) or "mirror" (one-way, read-only
	// copy). SeverPolicy is what a mirror does when home revokes it.
	Mode        string
	SeverPolicy string // "keep" | "purge"
	// MirrorAckedSeq (home side): highest home vault seq the mirror
	// acknowledged. HomeSeq (mirror side): highest home seq applied.
	MirrorAckedSeq    int64
	HomeSeq           int64
	LastContactAt     *time.Time
	PausedAt          *time.Time
	ResyncRequestedAt *time.Time
	PromotedAt        *time.Time
	// LastIntegrityAt (mirror side): last completed integrity pass.
	LastIntegrityAt *time.Time
	// Publish is the publish policy JSON of a publish mirror link (nil
	// for every other link); see federation.PublishPolicy.
	Publish []byte
}

// IsMirrorFollower reports whether this row makes the local vault a
// read-only mirror: a follower-side mirror link not promoted, whatever its
// status (a revoked mirror stays a frozen read-only copy).
func (f Federation) IsMirrorFollower() bool {
	return f.Role == "follower" && f.Mode == "mirror" && f.PromotedAt == nil
}

// FederationInvite is a single-use token a vault admin hands to another
// server's operator out-of-band; accepting it federates the vault.
type FederationInvite struct {
	Token         string
	VaultID       uuid.UUID
	InviterUserID uuid.UUID
	ServerURLHint string
	ExpiresAt     time.Time
	CreatedAt     time.Time
	UsedAt        *time.Time
	RevokedAt     *time.Time
	// Mode ("replica" | "mirror") and SeverPolicy ("keep" | "purge") are
	// fixed by home at invite time.
	Mode        string
	SeverPolicy string
	// Publish is the publish policy JSON (nil = not a publish mirror).
	Publish []byte
}

// PublishSetting is a mirror operator's opt-in to serve a publish mirror
// anonymously (publish_settings, migration 0012).
type PublishSetting struct {
	VaultID   uuid.UUID
	BasePath  string // "/p/<slug>"
	Robots    string // "noindex" | "index"
	EnabledAt time.Time
}
