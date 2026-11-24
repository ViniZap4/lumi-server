package admin

import (
	"bytes"
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// fakeStore is an in-memory Store. Tx methods append their audit entry
// only when the change succeeds, like the real store's transaction.
type fakeStore struct {
	mu           sync.Mutex
	tokens       map[uuid.UUID]*Token
	digests      map[uuid.UUID][]byte
	touches      int
	users        map[uuid.UUID]*User
	owned        map[uuid.UUID][]uuid.UUID
	sessions     map[string]*Session
	vaults       map[uuid.UUID]*Vault
	feds         map[uuid.UUID]*Federation
	members      map[uuid.UUID][]Member
	roles        map[uuid.UUID][]Role
	invites      map[string]*Invite
	audit        []domain.AuditEntry
	failAudit    bool
	promoteState []byte
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		tokens: map[uuid.UUID]*Token{}, digests: map[uuid.UUID][]byte{},
		users: map[uuid.UUID]*User{}, owned: map[uuid.UUID][]uuid.UUID{},
		sessions: map[string]*Session{}, vaults: map[uuid.UUID]*Vault{}, feds: map[uuid.UUID]*Federation{},
		members: map[uuid.UUID][]Member{}, roles: map[uuid.UUID][]Role{}, invites: map[string]*Invite{},
	}
}

func (f *fakeStore) addAudit(e domain.AuditEntry) error {
	if f.failAudit {
		return errAuditDown
	}
	e.ID = int64(len(f.audit) + 1)
	f.audit = append(f.audit, e)
	return nil
}

type auditErr struct{}

func (auditErr) Error() string { return "audit down" }

var errAuditDown = auditErr{}

func (f *fakeStore) CreateToken(_ context.Context, t Token, digest []byte, e domain.AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.addAudit(e); err != nil {
		return err
	}
	f.tokens[t.ID] = &t
	f.digests[t.ID] = digest
	return nil
}

func (f *fakeStore) TokenByDigest(_ context.Context, d []byte) (Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, dg := range f.digests {
		if bytes.Equal(dg, d) {
			return f.withUserLocked(*f.tokens[id]), nil
		}
	}
	return Token{}, domain.ErrNotFound
}

// withUserLocked fills a session's user fields like the store's join.
func (f *fakeStore) withUserLocked(t Token) Token {
	if t.UserID == nil {
		return t
	}
	u, ok := f.users[*t.UserID]
	t.Username, t.UserActive = "", false
	if ok {
		t.Username, t.UserActive = u.Username, u.ServerAdmin && u.DisabledAt == nil
	}
	return t
}

// revokeAdminSessionsLocked mirrors revokeAdminSessionsTx.
func (f *fakeStore) revokeAdminSessionsLocked(id uuid.UUID) {
	now := time.Now()
	for _, t := range f.tokens {
		if t.UserID != nil && *t.UserID == id && t.RevokedAt == nil {
			t.RevokedAt = &now
		}
	}
}

func (f *fakeStore) SetServerAdmin(_ context.Context, id uuid.UUID, enabled bool, e domain.AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[id]
	if !ok {
		return domain.ErrNotFound
	}
	if !enabled && u.ServerAdmin {
		others := 0
		for _, x := range f.users {
			if x.ID != id && x.ServerAdmin && x.DisabledAt == nil {
				others++
			}
		}
		if others == 0 {
			return ErrLastServerAdmin
		}
	}
	if err := f.addAudit(e); err != nil {
		return err
	}
	u.ServerAdmin = enabled
	if !enabled {
		f.revokeAdminSessionsLocked(id)
	}
	return nil
}

func (f *fakeStore) GetToken(_ context.Context, id uuid.UUID) (Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.tokens[id]
	if !ok {
		return Token{}, domain.ErrNotFound
	}
	return f.withUserLocked(*t), nil
}

func (f *fakeStore) TouchToken(_ context.Context, id uuid.UUID, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.touches++
	f.tokens[id].LastUsedAt = &at
	return nil
}

func (f *fakeStore) ListTokens(context.Context, *Cursor, int) ([]Token, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Token
	for _, t := range f.tokens {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out, false, nil
}

func (f *fakeStore) RevokeToken(_ context.Context, id uuid.UUID, at time.Time, e domain.AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.tokens[id]
	if !ok {
		return domain.ErrNotFound
	}
	if err := f.addAudit(e); err != nil {
		return err
	}
	if t.RevokedAt == nil {
		t.RevokedAt = &at
	}
	return nil
}

func (f *fakeStore) Counts(context.Context) (Counts, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return Counts{Users: int64(len(f.users)), Sessions: int64(len(f.sessions)), Vaults: int64(len(f.vaults)), SchemaVersion: 7}, nil
}

func (f *fakeStore) Ping(context.Context) error { return nil }

func (f *fakeStore) ListUsers(_ context.Context, flt UserFilter, after string, limit int) ([]User, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []User
	q := strings.ToLower(flt.Query)
	for _, u := range f.users {
		if q != "" && !strings.Contains(u.Username, q) && !strings.Contains(strings.ToLower(u.DisplayName), q) {
			continue
		}
		if flt.State != "" && u.State(time.Now()) != flt.State {
			continue
		}
		if flt.ServerAdmin && !u.ServerAdmin {
			continue
		}
		if u.Username > after {
			out = append(out, *u)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	more := limit > 0 && len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, nil
}

func (f *fakeStore) GetUser(_ context.Context, id uuid.UUID) (User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[id]
	if !ok {
		return User{}, domain.ErrNotFound
	}
	return *u, nil
}

func (f *fakeStore) GetUserByUsername(_ context.Context, name string) (User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.users {
		if u.Username == name {
			return *u, nil
		}
	}
	return User{}, domain.ErrNotFound
}

func (f *fakeStore) OwnedVaultIDs(_ context.Context, id uuid.UUID) ([]uuid.UUID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.owned[id], nil
}

func (f *fakeStore) CreateUser(_ context.Context, u domain.User, e domain.AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, x := range f.users {
		if x.Username == u.Username {
			return domain.ErrConflict
		}
	}
	if err := f.addAudit(e); err != nil {
		return err
	}
	f.users[u.ID] = &User{ID: u.ID, Username: u.Username, DisplayName: u.DisplayName, CreatedAt: u.CreatedAt}
	return nil
}

func (f *fakeStore) endSessions(id uuid.UUID) {
	for k, s := range f.sessions {
		if s.UserID == id {
			delete(f.sessions, k)
		}
	}
}

func (f *fakeStore) SetPassword(_ context.Context, id uuid.UUID, _ string, e domain.AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[id]
	if !ok {
		return domain.ErrNotFound
	}
	if err := f.addAudit(e); err != nil {
		return err
	}
	u.FailedLogins, u.LockedUntil = 0, nil
	f.endSessions(id)
	f.revokeAdminSessionsLocked(id)
	return nil
}

func (f *fakeStore) SetDisabled(_ context.Context, id uuid.UUID, disabled bool, e domain.AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[id]
	if !ok {
		return domain.ErrNotFound
	}
	if err := f.addAudit(e); err != nil {
		return err
	}
	if disabled {
		now := time.Now()
		u.DisabledAt = &now
		f.endSessions(id)
		f.revokeAdminSessionsLocked(id)
	} else {
		u.DisabledAt = nil
	}
	return nil
}

func (f *fakeStore) Unlock(_ context.Context, id uuid.UUID, e domain.AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.users[id]
	if !ok {
		return domain.ErrNotFound
	}
	if err := f.addAudit(e); err != nil {
		return err
	}
	u.FailedLogins, u.LockedUntil = 0, nil
	return nil
}

func (f *fakeStore) ListSessions(_ context.Context, uid *uuid.UUID, _ *Cursor, _ int) ([]Session, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Session
	for _, s := range f.sessions {
		if uid == nil || s.UserID == *uid {
			out = append(out, *s)
		}
	}
	return out, false, nil
}

func (f *fakeStore) GetSession(_ context.Context, id string) (Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[id]
	if !ok {
		return Session{}, domain.ErrNotFound
	}
	return *s, nil
}

func (f *fakeStore) DeleteSession(_ context.Context, id string, e domain.AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.sessions[id]; !ok {
		return domain.ErrNotFound
	}
	if err := f.addAudit(e); err != nil {
		return err
	}
	delete(f.sessions, id)
	return nil
}

func (f *fakeStore) ListVaults(_ context.Context, flt VaultFilter, _ string, _ int) ([]Vault, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Vault
	q := strings.ToLower(flt.Query)
	for _, v := range f.vaults {
		if q != "" && !strings.Contains(v.Slug, q) && !strings.Contains(strings.ToLower(v.Name), q) {
			continue
		}
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out, false, nil
}

func (f *fakeStore) VaultMembers(_ context.Context, id uuid.UUID) ([]Member, []Role, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.members[id], f.roles[id], nil
}

func (f *fakeStore) EndUserSessions(_ context.Context, id uuid.UUID, e func(int) domain.AuditEntry) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.users[id]; !ok {
		return 0, domain.ErrNotFound
	}
	n := 0
	for _, s := range f.sessions {
		if s.UserID == id {
			n++
		}
	}
	if err := f.addAudit(e(n)); err != nil {
		return 0, err
	}
	f.endSessions(id)
	f.revokeAdminSessionsLocked(id)
	return n, nil
}

func (f *fakeStore) ListInvites(_ context.Context, flt InviteFilter, _ *Cursor, _ int) ([]Invite, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Invite
	for _, i := range f.invites {
		if flt.VaultID != nil && i.VaultID != *flt.VaultID {
			continue
		}
		if flt.ActiveOnly && i.State(time.Now()) != "active" {
			continue
		}
		out = append(out, *i)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].CreatedAt.After(out[b].CreatedAt) })
	return out, false, nil
}

func (f *fakeStore) GetInvite(_ context.Context, id string) (Invite, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	i, ok := f.invites[id]
	if !ok {
		return Invite{}, domain.ErrNotFound
	}
	return *i, nil
}

func (f *fakeStore) RevokeInvite(_ context.Context, id string, at time.Time, e domain.AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	i, ok := f.invites[id]
	if !ok {
		return domain.ErrNotFound
	}
	if err := f.addAudit(e); err != nil {
		return err
	}
	if i.RevokedAt == nil {
		i.RevokedAt = &at
	}
	return nil
}

func (f *fakeStore) GetVault(_ context.Context, id uuid.UUID) (Vault, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.vaults[id]
	if !ok {
		return Vault{}, domain.ErrNotFound
	}
	return *v, nil
}

func (f *fakeStore) GetVaultBySlug(_ context.Context, slug string) (Vault, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, v := range f.vaults {
		if v.Slug == slug {
			return *v, nil
		}
	}
	return Vault{}, domain.ErrNotFound
}

func (f *fakeStore) ListFederations(_ context.Context, filter FederationFilter, _ *Cursor, _ int) ([]Federation, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Federation
	for _, x := range f.feds {
		if filter.Mode != "" && x.Mode != filter.Mode {
			continue
		}
		out = append(out, *x)
	}
	return out, false, nil
}

func (f *fakeStore) PromoteMirror(_ context.Context, vaultID uuid.UUID, now time.Time, plan func([]byte) (Promotion, error), entry func(PromoteResult) domain.AuditEntry) (PromoteResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, x := range f.feds {
		if x.VaultID == vaultID && x.Role == "follower" && x.Mode == "mirror" && x.PromotedAt == nil {
			p, err := plan(f.promoteState)
			if err != nil {
				return PromoteResult{}, err
			}
			t := now
			x.PromotedAt = &t
			res := PromoteResult{FederationID: x.ID, PeerURL: x.PeerURL, Dropped: p.Dropped}
			for _, m := range p.Members {
				res.Members = append(res.Members, m.Username+":"+m.Role)
			}
			f.audit = append(f.audit, entry(res))
			return res, nil
		}
	}
	return PromoteResult{}, domain.ErrNotFound
}

func (f *fakeStore) GetFederation(_ context.Context, id uuid.UUID) (Federation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	x, ok := f.feds[id]
	if !ok {
		return Federation{}, domain.ErrNotFound
	}
	return *x, nil
}

func (f *fakeStore) RecordAudit(_ context.Context, e domain.AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.addAudit(e)
}

func (f *fakeStore) ListAudit(_ context.Context, q AuditQuery) ([]domain.AuditEntry, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []domain.AuditEntry
	for i := len(f.audit) - 1; i >= 0; i-- {
		e := f.audit[i]
		if q.Before > 0 && e.ID >= q.Before {
			continue
		}
		if q.Action != "" && ((q.ActionPrefix && !strings.HasPrefix(e.Action, q.Action)) || (!q.ActionPrefix && e.Action != q.Action)) {
			continue
		}
		if (q.Since != nil && e.CreatedAt.Before(*q.Since)) || (q.Until != nil && !e.CreatedAt.Before(*q.Until)) {
			continue
		}
		out = append(out, e)
	}
	more := q.Limit > 0 && len(out) > q.Limit
	if more {
		out = out[:q.Limit]
	}
	return out, more, nil
}

func (f *fakeStore) lastAudit() domain.AuditEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.audit) == 0 {
		return domain.AuditEntry{}
	}
	return f.audit[len(f.audit)-1]
}

func (f *fakeStore) auditCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.audit)
}

// ---- collaborators ----------------------------------------------------------------

type eraseCall struct {
	id    uuid.UUID
	force bool
	ip    string
}

type fakeEraser struct {
	store *fakeStore
	calls []eraseCall
}

func (e *fakeEraser) Delete(_ context.Context, id uuid.UUID, force bool, ip, _ *string) error {
	c := eraseCall{id: id, force: force}
	if ip != nil {
		c.ip = *ip
	}
	e.calls = append(e.calls, c)
	e.store.mu.Lock()
	defer e.store.mu.Unlock()
	delete(e.store.users, id)
	return nil
}

type fakeVaults struct{ deleted []uuid.UUID }

func (v *fakeVaults) Delete(_ context.Context, id, _ uuid.UUID, _, _ string) error {
	v.deleted = append(v.deleted, id)
	return nil
}

type fakeFeds struct{ revoked []uuid.UUID }

func (r *fakeFeds) RevokeFederation(_ context.Context, _, id, _ uuid.UUID, _, _ string) error {
	r.revoked = append(r.revoked, id)
	return nil
}

type plainHasher struct{}

func (plainHasher) HashPassword(pw string) (string, error) { return "hash:" + pw, nil }

type fakeLive struct {
	mu       sync.Mutex
	users    []uuid.UUID
	sessKeys []string
}

func (l *fakeLive) UserSessionsEnded(id uuid.UUID, _ string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.users = append(l.users, id)
}

func (l *fakeLive) SessionKeyEnded(k, _ string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sessKeys = append(l.sessKeys, k)
}

type fixture struct {
	store  *fakeStore
	eraser *fakeEraser
	vaults *fakeVaults
	feds   *fakeFeds
	live   *fakeLive
	svc    *Service
}

func newFixture() *fixture {
	st := newFakeStore()
	f := &fixture{store: st, eraser: &fakeEraser{store: st}, vaults: &fakeVaults{}, feds: &fakeFeds{}, live: &fakeLive{}}
	f.svc = &Service{Store: st, Users: f.eraser, Vaults: f.vaults, Federations: f.feds,
		Hasher: plainHasher{}, Live: f.live, Version: "test"}
	return f
}

func (f *fixture) addUser(name string) *User {
	u := &User{ID: uuid.New(), Username: name, CreatedAt: time.Now()}
	f.store.users[u.ID] = u
	return u
}
