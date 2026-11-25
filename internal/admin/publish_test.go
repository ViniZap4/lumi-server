package admin

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

type fakePublish struct {
	mu     sync.Mutex
	rows   map[uuid.UUID]domain.PublishSetting
	audits []domain.AuditEntry
}

func (f *fakePublish) Upsert(_ context.Context, p domain.PublishSetting, e domain.AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id, r := range f.rows {
		if r.BasePath == p.BasePath && id != p.VaultID {
			return domain.ErrConflict
		}
	}
	f.rows[p.VaultID] = p
	f.audits = append(f.audits, e)
	return nil
}

func (f *fakePublish) Delete(_ context.Context, id uuid.UUID, e domain.AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.rows[id]; !ok {
		return domain.ErrNotFound
	}
	delete(f.rows, id)
	f.audits = append(f.audits, e)
	return nil
}

func (f *fakePublish) List(context.Context) ([]domain.PublishSetting, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []domain.PublishSetting
	for _, r := range f.rows {
		out = append(out, r)
	}
	return out, nil
}

func TestPublishEnable_NeedsOwnerConsent(t *testing.T) {
	f := newFixture()
	pub := &fakePublish{rows: map[uuid.UUID]domain.PublishSetting{}}
	f.svc.Publish = pub
	ctx := context.Background()
	mk := func(slug string, fed *Federation) *Vault {
		v := &Vault{ID: uuid.New(), Slug: slug, Name: slug, CreatedAt: time.Now()}
		f.store.vaults[v.ID] = v
		if fed != nil {
			fed.ID, fed.VaultID = uuid.New(), v.ID
			f.store.feds[fed.ID] = fed
		}
		return v
	}
	local := mk("local", nil)
	private := mk("private", &Federation{Role: "follower", Mode: "mirror", Status: "active"})
	home := mk("homebook", &Federation{Role: "home", Mode: "mirror", Status: "active", Publish: []byte(`{"allowed":true,"scope":"all"}`)})
	ok := mk("blog", &Federation{Role: "follower", Mode: "mirror", Status: "active", Publish: []byte(`{"allowed":true,"scope":"flagged"}`)})

	var ie *InvalidError
	for _, v := range []*Vault{local, private, home} {
		if _, err := f.svc.EnablePublish(ctx, CLI, v.Slug, "x"+v.Slug, ""); !errors.As(err, &ie) {
			t.Fatalf("%s: %v", v.Slug, err)
		}
	}
	for _, bad := range []string{"", "-x", "UP", "a/b", "../x"} {
		if _, err := f.svc.EnablePublish(ctx, CLI, ok.Slug, bad, ""); !errors.As(err, &ie) {
			t.Fatalf("slug %q accepted", bad)
		}
	}
	if _, err := f.svc.EnablePublish(ctx, CLI, ok.Slug, "blog", "always"); !errors.As(err, &ie) {
		t.Fatal("bad robots accepted")
	}
	p, err := f.svc.EnablePublish(ctx, CLI, ok.Slug, "blog", "")
	if err != nil {
		t.Fatal(err)
	}
	if p.BasePath != "/p/blog" || p.Robots != "noindex" || p.Scope != "flagged" || pub.rows[ok.ID].BasePath != "/p/blog" {
		t.Fatalf("publication %+v", p)
	}
	if len(pub.audits) != 1 || pub.audits[0].Action != ActionPublishEnable {
		t.Fatalf("audits %+v", pub.audits)
	}
	list, err := f.svc.ListPublish(ctx)
	if err != nil || len(list) != 1 || list[0].Vault.Slug != "blog" || list[0].Status != "active" {
		t.Fatalf("list %+v %v", list, err)
	}
	if err := f.svc.DisablePublish(ctx, CLI, ok.Slug); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.DisablePublish(ctx, CLI, ok.Slug); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("second disable: %v", err)
	}
}
