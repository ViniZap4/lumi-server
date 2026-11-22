package admin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

func TestStatusExtraFields(t *testing.T) {
	h := newHarness(t)
	st := h.do(t, "GET", "/admin/v1/status", h.token, "").json(t)
	for _, k := range []string{"db_latency_ms", "users_disabled", "users_locked", "crdt_bytes", "logins_24h",
		"login_failures_24h", "invites_active", "go_version"} {
		if _, ok := st[k]; !ok {
			t.Errorf("status without %q: %v", k, st)
		}
	}
	if v, _ := st["go_version"].(string); !strings.HasPrefix(v, "go") {
		t.Errorf("go_version %v", st["go_version"])
	}
}

func TestUserSearchAndLastSeen(t *testing.T) {
	h := newHarness(t)
	alice := h.addUser("alice")
	alice.DisplayName = "Alice Wonder"
	now := time.Now()
	alice.LastLoginAt, alice.LastSeenAt = &now, &now
	bob := h.addUser("bob")
	bob.DisabledAt = &now
	carol := h.addUser("carol")
	later := now.Add(time.Hour)
	carol.LockedUntil = &later

	names := func(q string) []string {
		t.Helper()
		r := h.do(t, "GET", "/admin/v1/users?"+q, h.token, "")
		if r.status != 200 {
			t.Fatalf("%s: %d %s", q, r.status, r.body)
		}
		var out []string
		for _, it := range r.json(t)["items"].([]any) {
			out = append(out, it.(map[string]any)["username"].(string))
		}
		return out
	}
	if got := names("q=WONDER"); len(got) != 1 || got[0] != "alice" {
		t.Fatalf("q by display name: %v", got)
	}
	if got := names("q=ro"); len(got) != 1 || got[0] != "carol" {
		t.Fatalf("q=ro: %v", got)
	}
	for st, want := range map[string]string{"disabled": "bob", "locked": "carol", "active": "alice"} {
		if got := names("state=" + st); len(got) != 1 || got[0] != want {
			t.Errorf("state=%s: %v", st, got)
		}
	}
	for _, q := range []string{"state=gone", "q=" + strings.Repeat("x", 65), "q=a%01b"} {
		r := h.do(t, "GET", "/admin/v1/users?"+q, h.token, "")
		if r.status != 400 || r.json(t)["error"] != "validation_failed" {
			t.Errorf("%s: %d %s", q, r.status, r.body)
		}
	}
	m := h.do(t, "GET", "/admin/v1/users/"+alice.ID.String(), h.token, "").json(t)
	if m["last_login_at"] == nil || m["last_seen_at"] == nil {
		t.Fatalf("detail %v", m)
	}
	m = h.do(t, "GET", "/admin/v1/users/"+bob.ID.String(), h.token, "").json(t)
	if v, ok := m["last_login_at"]; !ok || v != nil {
		t.Fatalf("bob last_login_at %v", m)
	}
}

func TestEndUserSessions(t *testing.T) {
	h := newHarness(t)
	u := h.addUser("dave")
	other := h.addUser("erin")
	for i, uid := range []uuid.UUID{u.ID, u.ID, other.ID} {
		id := strings.Repeat(string(rune('a'+i)), 64)
		h.store.sessions[id] = &Session{ID: id, UserID: uid, Username: "x"}
	}
	r := h.do(t, "DELETE", "/admin/v1/users/"+u.ID.String()+"/sessions", h.token, "")
	if r.status != 200 || r.json(t)["revoked"].(float64) != 2 {
		t.Fatalf("end sessions: %d %s", r.status, r.body)
	}
	a := checkAdminAudit(t, h, ActionUserLogout, &u.ID)
	var p map[string]any
	_ = json.Unmarshal(a.Payload, &p)
	if p["username"] != "dave" || p["sessions"].(float64) != 2 {
		t.Fatalf("payload %s", a.Payload)
	}
	if len(h.store.sessions) != 1 || len(h.live.users) != 1 || h.live.users[0] != u.ID {
		t.Fatalf("sessions %d live %v", len(h.store.sessions), h.live.users)
	}
	// Audited even with none left.
	n := h.store.auditCount()
	r = h.do(t, "DELETE", "/admin/v1/users/"+u.ID.String()+"/sessions", h.token, "")
	if r.status != 200 || r.json(t)["revoked"].(float64) != 0 || h.store.auditCount() != n+1 {
		t.Fatalf("second: %d %s", r.status, r.body)
	}
	for _, p := range []string{uuid.NewString(), "nope"} {
		if r := h.do(t, "DELETE", "/admin/v1/users/"+p+"/sessions", h.token, ""); r.status != 404 {
			t.Errorf("unknown %s: %d", p, r.status)
		}
	}
	// No audit, no change when the transaction fails.
	h.store.sessions[strings.Repeat("f", 64)] = &Session{ID: strings.Repeat("f", 64), UserID: other.ID}
	h.store.failAudit = true
	n = h.store.auditCount()
	if r := h.do(t, "DELETE", "/admin/v1/users/"+other.ID.String()+"/sessions", h.token, ""); r.status != 500 {
		t.Fatalf("audit down: %d", r.status)
	}
	if h.store.auditCount() != n || len(h.store.sessions) != 2 {
		t.Fatalf("changed without audit")
	}
}

func TestVaultSearchAndMembers(t *testing.T) {
	h := newHarness(t)
	owner := h.addUser("olga")
	member := h.addUser("pete")
	now := time.Now()
	v := &Vault{ID: uuid.New(), Slug: "garden", Name: "Jardim", OwnerID: owner.ID, OwnerUsername: "olga",
		HeadSeq: 42, LastChangeAt: &now, InvitesActive: 1, CreatedAt: now}
	h.store.vaults[v.ID] = v
	h.store.vaults[uuid.New()] = &Vault{ID: uuid.New(), Slug: "work", Name: "Trabalho", CreatedAt: now}
	admin, viewer := uuid.New(), uuid.New()
	h.store.members[v.ID] = []Member{
		{UserID: owner.ID, Username: "olga", RoleID: admin, RoleName: "Admin", Owner: true, JoinedAt: now},
		{UserID: member.ID, Username: "pete", DisplayName: "Pete", RoleID: viewer, RoleName: "Viewer", JoinedAt: now},
	}
	h.store.roles[v.ID] = []Role{{ID: admin, Name: "Admin", Seed: true, Members: 1}, {ID: viewer, Name: "Viewer", Seed: true, Members: 1}}

	r := h.do(t, "GET", "/admin/v1/vaults?q=JARD", h.token, "").json(t)
	items := r["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("q: %v", r)
	}
	got := items[0].(map[string]any)
	if got["head_seq"].(float64) != 42 || got["last_change_at"] == nil || got["invites_active"].(float64) != 1 {
		t.Fatalf("vault json %v", got)
	}
	if r := h.do(t, "GET", "/admin/v1/vaults?q="+strings.Repeat("x", 65), h.token, ""); r.status != 400 {
		t.Fatalf("long q: %d", r.status)
	}

	m := h.do(t, "GET", "/admin/v1/vaults/"+v.ID.String()+"/members", h.token, "")
	if m.status != 200 {
		t.Fatalf("members: %d %s", m.status, m.body)
	}
	body := m.json(t)
	ms := body["members"].([]any)
	first := ms[0].(map[string]any)
	if len(ms) != 2 || first["owner"] != true || first["user"].(map[string]any)["username"] != "olga" ||
		first["role"].(map[string]any)["name"] != "Admin" || first["joined_at"] == nil {
		t.Fatalf("members %v", body)
	}
	roles := body["roles"].([]any)
	if len(roles) != 2 || roles[0].(map[string]any)["seed"] != true || roles[0].(map[string]any)["members"].(float64) != 1 {
		t.Fatalf("roles %v", roles)
	}
	for _, p := range []string{uuid.NewString(), "nope"} {
		if r := h.do(t, "GET", "/admin/v1/vaults/"+p+"/members", h.token, ""); r.status != 404 {
			t.Errorf("unknown %s: %d", p, r.status)
		}
	}
}

func TestInviteRoutes(t *testing.T) {
	h := newHarness(t)
	now := time.Now()
	vault := uuid.New()
	other := uuid.New()
	mk := func(token string, vid uuid.UUID, mod func(*Invite)) *Invite {
		sum := sha256.Sum256([]byte(token))
		i := &Invite{ID: hex.EncodeToString(sum[:]), VaultID: vid, VaultSlug: "garden", InviterID: uuid.New(),
			InviterUsername: "olga", RoleID: uuid.New(), RoleName: "Editor", MaxUses: 2, UseCount: 0,
			ExpiresAt: now.Add(time.Hour), CreatedAt: now}
		if mod != nil {
			mod(i)
		}
		h.store.invites[i.ID] = i
		return i
	}
	active := mk("secret-token-active", vault, nil)
	mk("secret-token-expired", vault, func(i *Invite) { i.ExpiresAt = now.Add(-time.Minute); i.CreatedAt = now.Add(-time.Hour) })
	mk("secret-token-used", vault, func(i *Invite) { i.UseCount = 2; i.CreatedAt = now.Add(-2 * time.Hour) })
	mk("secret-token-revoked", other, func(i *Invite) { i.RevokedAt = &now; i.ExpiresAt = now.Add(-time.Minute) })

	r := h.do(t, "GET", "/admin/v1/invites", h.token, "")
	if r.status != 200 {
		t.Fatalf("list: %d %s", r.status, r.body)
	}
	if strings.Contains(r.body, "secret-token") {
		t.Fatal("invite token leaked")
	}
	states := map[string]string{}
	for _, it := range r.json(t)["items"].([]any) {
		m := it.(map[string]any)
		states[m["id"].(string)] = m["state"].(string)
		if len(m["id"].(string)) != 64 || m["vault"].(map[string]any)["slug"] != "garden" {
			t.Fatalf("invite json %v", m)
		}
	}
	want := map[string]int{"active": 1, "expired": 1, "exhausted": 1, "revoked": 1}
	got := map[string]int{}
	for _, s := range states {
		got[s]++
	}
	for k, n := range want {
		if got[k] != n {
			t.Fatalf("states %v", states)
		}
	}
	if items := h.do(t, "GET", "/admin/v1/invites?state=active", h.token, "").json(t)["items"].([]any); len(items) != 1 {
		t.Fatalf("active filter %v", items)
	}
	if items := h.do(t, "GET", "/admin/v1/invites?vault="+other.String(), h.token, "").json(t)["items"].([]any); len(items) != 1 {
		t.Fatalf("vault filter %v", items)
	}
	for _, q := range []string{"state=x", "vault=1", "limit=0"} {
		if r := h.do(t, "GET", "/admin/v1/invites?"+q, h.token, ""); r.status != 400 {
			t.Errorf("%s: %d", q, r.status)
		}
	}

	// Revoke: audited, idempotent.
	if r := h.do(t, "DELETE", "/admin/v1/invites/"+active.ID, h.token, ""); r.status != 204 {
		t.Fatalf("revoke: %d %s", r.status, r.body)
	}
	a := checkAdminAudit(t, h, ActionInviteRevoke, nil)
	if a.VaultID == nil || *a.VaultID != vault || !strings.Contains(string(a.Payload), `"invite_id":"`+active.ID[:12]+`"`) ||
		strings.Contains(string(a.Payload), active.ID) || !strings.Contains(string(a.Payload), `"vault_slug":"garden"`) {
		t.Fatalf("audit %s", a.Payload)
	}
	if h.store.invites[active.ID].RevokedAt == nil {
		t.Fatal("not revoked")
	}
	n := h.store.auditCount()
	if r := h.do(t, "DELETE", "/admin/v1/invites/"+active.ID, h.token, ""); r.status != 204 || h.store.auditCount() != n+1 {
		t.Fatalf("second revoke: %d", r.status)
	}
	for _, id := range []string{strings.Repeat("0", 64), "abc", strings.Repeat("A", 64)} {
		if r := h.do(t, "DELETE", "/admin/v1/invites/"+id, h.token, ""); r.status != 404 {
			t.Errorf("unknown %s: %d", id, r.status)
		}
	}
	// Audit down: nothing changes.
	fresh := mk("secret-token-fresh", vault, nil)
	h.store.failAudit = true
	if r := h.do(t, "DELETE", "/admin/v1/invites/"+fresh.ID, h.token, ""); r.status != 500 {
		t.Fatalf("audit down: %d", r.status)
	}
	if h.store.invites[fresh.ID].RevokedAt != nil {
		t.Fatal("revoked without audit")
	}
}

func TestAuditFilters(t *testing.T) {
	h := newHarness(t)
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for i, action := range []string{"auth.login", "auth.login_failed", "vault.create", "auth.logout"} {
		_ = h.store.addAudit(auditAt(action, base.Add(time.Duration(i)*time.Hour)))
	}
	count := func(q string) int {
		t.Helper()
		r := h.do(t, "GET", "/admin/v1/audit?"+q, h.token, "")
		if r.status != 200 {
			t.Fatalf("%s: %d %s", q, r.status, r.body)
		}
		return len(r.json(t)["entries"].([]any))
	}
	if n := count("action=auth.login"); n != 1 {
		t.Errorf("exact: %d", n)
	}
	if n := count("action=auth.*"); n != 3 {
		t.Errorf("prefix: %d", n)
	}
	if n := count("since=2026-01-01T13:00:00Z&until=2026-01-01T15:00:00Z"); n != 2 {
		t.Errorf("range: %d", n)
	}
	if n := count("action=auth.*&since=2026-01-01T14:00:00Z"); n != 1 {
		t.Errorf("prefix+since: %d", n)
	}
	for _, q := range []string{"action=Auth", "action=auth.", "action=auth*", "action=a.*.b", "action=" + strings.Repeat("a", 65),
		"since=yesterday", "until=2026-01-01", "since=2026-01-02T00:00:00Z&until=2026-01-01T00:00:00Z",
		"since=2026-01-01T00:00:00Z&until=2026-01-01T00:00:00Z"} {
		r := h.do(t, "GET", "/admin/v1/audit?"+q, h.token, "")
		if r.status != 400 || r.json(t)["field"] == nil {
			t.Errorf("%s: %d %s", q, r.status, r.body)
		}
	}
}

func auditAt(action string, at time.Time) domain.AuditEntry {
	return domain.AuditEntry{Action: action, CreatedAt: at, Payload: []byte(`{}`)}
}
