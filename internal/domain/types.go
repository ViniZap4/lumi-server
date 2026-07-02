// Package domain holds canonical types shared across the server. Types are
// pure data: no behaviour, no I/O. Service packages embed or wrap these.
package domain

import (
	"time"

	"github.com/google/uuid"
)

// User represents a server-scoped account. Identity is independent per server
// (no central identity provider). See SPEC.md "Identity".
type User struct {
	ID           uuid.UUID
	Username     string
	PasswordHash string
	DisplayName  string
	CreatedAt    time.Time
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
type Note struct {
	ID        string
	VaultID   uuid.UUID
	Path      string
	Title     string
	CreatedAt time.Time
	UpdatedAt time.Time
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
	ActionAuthLogin          = "auth.login"
	ActionAuthLoginFailed    = "auth.login_failed"
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
	CreatedAt    time.Time
	RevokedAt    *time.Time
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
}
