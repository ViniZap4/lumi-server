package domain

import "strings"

// Capability is a permission identifier in dotted form. Examples: "note.read",
// "members.invite", "vault.manage". The wildcards "*" and "<prefix>.*" are
// allowed in CapabilitySet values (not in capability lookup needles).
type Capability string

// Built-in capability constants. Keep this list in sync with SPEC.md
// "Capability vocabulary".
const (
	CapAll Capability = "*"

	CapNoteRead   Capability = "note.read"
	CapNoteCreate Capability = "note.create"
	CapNoteEdit   Capability = "note.edit"
	CapNoteDelete Capability = "note.delete"
	CapNoteMove   Capability = "note.move"
	CapNoteAll    Capability = "note.*"

	CapMembersInvite Capability = "members.invite"
	CapMembersManage Capability = "members.manage"
	CapMembersAll    Capability = "members.*"

	CapRolesManage Capability = "roles.manage"
	CapRolesAll    Capability = "roles.*"

	CapVaultManage Capability = "vault.manage"
	CapVaultExport Capability = "vault.export"
	CapVaultAll    Capability = "vault.*"

	CapAuditRead Capability = "audit.read"
)

// CapabilitySet is the capability list granted to a role. Values may include
// wildcards. Use Has() rather than membership tests; wildcards must expand.
type CapabilitySet []Capability

// Has reports whether the set grants the requested capability.
//
// Wildcard semantics:
//   - "*" matches any capability.
//   - "note.*" matches "note.read", "note.edit", etc., but not "note" alone.
//   - exact strings match themselves only.
//
// The needle should not contain wildcards.
func (cs CapabilitySet) Has(c Capability) bool {
	needle := string(c)
	for _, granted := range cs {
		s := string(granted)
		if s == "*" || s == needle {
			return true
		}
		if strings.HasSuffix(s, ".*") {
			prefix := strings.TrimSuffix(s, "*") // keeps trailing dot
			if strings.HasPrefix(needle, prefix) && len(needle) > len(prefix) {
				return true
			}
		}
	}
	return false
}

// SeedRoles returns the canonical seed-role definitions. Vault creation seeds
// these into vault_roles with is_seed = true.
func SeedRoles() map[string]CapabilitySet {
	return map[string]CapabilitySet{
		"Admin": {CapAll},
		"Editor": {
			CapNoteRead, CapNoteCreate, CapNoteEdit, CapNoteDelete, CapNoteMove,
		},
		"Viewer":    {CapNoteRead},
		"Commenter": {CapNoteRead}, // upgraded when comments ship (post-v2.0)
	}
}
