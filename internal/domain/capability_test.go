package domain

import "testing"

func TestCapabilitySet_Covers(t *testing.T) {
	cases := []struct {
		name   string
		holder CapabilitySet
		target CapabilitySet
		want   bool
	}{
		{"empty target", CapabilitySet{CapNoteRead}, nil, true},
		{"admin covers all", CapabilitySet{CapAll}, CapabilitySet{CapAll, CapMembersManage}, true},
		{"exact subset", CapabilitySet{CapNoteRead, CapNoteEdit}, CapabilitySet{CapNoteRead}, true},
		{"family wildcard covers member", CapabilitySet{CapNoteAll}, CapabilitySet{CapNoteRead, CapNoteDelete}, true},
		{"family wildcard covers itself", CapabilitySet{CapNoteAll}, CapabilitySet{CapNoteAll}, true},
		{"invite-only cannot grant admin", CapabilitySet{CapMembersInvite}, CapabilitySet{CapAll}, false},
		{"manage cannot grant star", CapabilitySet{CapMembersManage, CapNoteAll}, CapabilitySet{CapAll}, false},
		{"exact does not cover family", CapabilitySet{CapNoteRead}, CapabilitySet{CapNoteAll}, false},
		{"other family", CapabilitySet{CapNoteAll}, CapabilitySet{CapMembersInvite}, false},
		{"members.* does not cover roles", CapabilitySet{CapMembersAll}, CapabilitySet{CapRolesManage}, false},
		{"empty holder", nil, CapabilitySet{CapNoteRead}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.holder.Covers(tc.target); got != tc.want {
				t.Fatalf("Covers(%v, %v) = %v, want %v", tc.holder, tc.target, got, tc.want)
			}
		})
	}
}
