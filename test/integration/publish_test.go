//go:build integration

package integration

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// anonGet fetches a public URL with no credentials.
func anonGet(t *testing.T, s *server, path string) (int, string, http.Header) {
	t.Helper()
	resp, err := http.Get(s.base + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

// TestTwoServerPublishMirror is A19 #8 and #9 (purge): a publish mirror
// with scope "flagged" only ever receives notes whose frontmatter says
// publish: true; the anonymous endpoints never show anything else; the
// flag toggles publication both ways; revoking purges the mirror (the
// default sever policy of publish mirrors).
func TestTwoServerPublishMirror(t *testing.T) {
	adminURL := postgresAdminURL(t)
	a := startServer(t, "a", createDatabase(t, adminURL, "lumi_it_pub_a"))
	b := startServer(t, "b", createDatabase(t, adminURL, "lumi_it_pub_b"), "LUMI_PUBLISH_ENABLED=true")
	const wait = 30 * time.Second
	aAdmin := a.login(t, a.admin, a.pass)
	bAdmin := b.login(t, b.admin, b.pass)

	var vault struct {
		ID string `json:"id"`
	}
	aAdmin.mustDo(http.MethodPost, "/api/vaults", map[string]string{"name": "Public Book"}, http.StatusCreated, &vault)
	V := vault.ID
	var post, diary struct {
		ID string `json:"id"`
	}
	aAdmin.mustDo(http.MethodPost, "/api/vaults/"+V+"/notes", map[string]any{"title": "Hello Post", "body": "public words\n"}, http.StatusCreated, &post)
	aAdmin.mustDo(http.MethodPatch, "/api/vaults/"+V+"/notes/"+post.ID, map[string]any{"publish": true}, http.StatusOK, nil)
	aAdmin.mustDo(http.MethodPost, "/api/vaults/"+V+"/notes", map[string]any{"title": "Secret Diary", "body": "SECRET BODY\n", "tags": []string{"private"}}, http.StatusCreated, &diary)

	// Publishing needs vault.manage + vault.federate (owner) and mirror mode.
	status, raw := aAdmin.do(http.MethodPost, "/api/vaults/"+V+"/federation-invites",
		map[string]any{"server_url_hint": b.base, "publish": map[string]any{"allowed": true}}, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("publish on a replica invite: %d %s", status, raw)
	}
	var inv struct {
		Token       string         `json:"token"`
		SeverPolicy string         `json:"sever_policy"`
		Publish     map[string]any `json:"publish"`
	}
	aAdmin.mustDo(http.MethodPost, "/api/vaults/"+V+"/federation-invites",
		map[string]any{"server_url_hint": b.base, "mode": "mirror", "publish": map[string]any{"allowed": true, "scope": "flagged"}},
		http.StatusCreated, &inv)
	if inv.SeverPolicy != "purge" || inv.Publish["scope"] != "flagged" {
		t.Fatalf("publish invite %+v", inv)
	}
	bAdmin.mustDo(http.MethodPost, "/api/federation/join", map[string]string{"home_url": a.base, "token": inv.Token, "mode": "mirror"}, http.StatusCreated, nil)

	// Before the operator opts in: nothing is public.
	if st, _, _ := anonGet(t, b, "/api/public/books/blog"); st != http.StatusNotFound {
		t.Fatalf("before publish enable: %d", st)
	}
	eventually(t, wait, "published note replicated", func() string {
		var n int
		if err := b.query(t, `SELECT count(*) FROM notes WHERE vault_id = $1 AND id = $2`, V, post.ID).Scan(&n); err != nil || n != 1 {
			return fmt.Sprintf("%d %v", n, err)
		}
		return ""
	})
	out := b.cli(t, "publish", "enable", V, "--slug", "blog")
	if !strings.Contains(out, "/p/blog") {
		t.Fatalf("publish enable: %s", out)
	}

	noLeak := func(when string) {
		t.Helper()
		var n int
		if err := b.query(t, `SELECT count(*) FROM notes WHERE vault_id = $1 AND id = $2`, V, diary.ID).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s: unpublished note reached the mirror (%d %v)", when, n, err)
		}
		var tomb int
		if err := b.query(t, `SELECT count(*) FROM note_tombstones WHERE vault_id = $1 AND note_id = $2`, V, diary.ID).Scan(&tomb); err != nil || tomb != 0 {
			t.Fatalf("%s: the unpublished id reached the mirror as a tombstone (%d %v)", when, tomb, err)
		}
		var members string
		if err := b.query(t, `SELECT state::text FROM replicated_control_state WHERE vault_id = $1`, V).Scan(&members); err != nil {
			t.Fatalf("%s: no control state on the mirror: %v", when, err)
		}
		if !strings.Contains(members, "Public Book") || strings.Contains(members, a.admin+"@") {
			t.Fatalf("%s: home's members reached the publish mirror: %s", when, members)
		}
		for _, p := range []string{"/api/public/books/blog", "/api/public/books/blog/notes/" + diary.ID} {
			_, body, _ := anonGet(t, b, p)
			for _, s := range []string{"Secret", "SECRET", "diary", "private", a.admin} {
				if strings.Contains(body, s) {
					t.Fatalf("%s: %s leaked %q: %s", when, p, s, body)
				}
			}
		}
	}

	eventually(t, wait, "public listing", func() string {
		st, body, hdr := anonGet(t, b, "/api/public/books/blog")
		if st != http.StatusOK || !strings.Contains(body, `"Hello Post"`) || !strings.Contains(body, `"Public Book"`) {
			return fmt.Sprintf("%d %s", st, body)
		}
		if hdr.Get("Cache-Control") != "public, max-age=60" || hdr.Get("X-Robots-Tag") == "" || hdr.Get("Set-Cookie") != "" {
			return fmt.Sprintf("headers %v", hdr)
		}
		return ""
	})
	eventually(t, wait, "public note body", func() string {
		st, body, _ := anonGet(t, b, "/api/public/books/blog/notes/"+post.ID)
		if st != http.StatusOK || !strings.Contains(body, "public words") {
			return fmt.Sprintf("%d %s", st, body)
		}
		return ""
	})
	if st, _, _ := anonGet(t, b, "/api/public/books/blog/notes/"+diary.ID); st != http.StatusNotFound {
		t.Fatalf("unpublished note: %d", st)
	}
	noLeak("published")

	// Things happen to the private note at home: still nothing crosses.
	aAdmin.editREST(V, diary.ID, func(s string) string { return s + "more secrets\n" })
	aAdmin.mustDo(http.MethodPatch, "/api/vaults/"+V+"/notes/"+diary.ID, map[string]any{"tags": []string{"private", "x"}}, http.StatusOK, nil)
	aAdmin.mustDo(http.MethodPatch, "/api/vaults/"+V+"/notes/"+diary.ID, map[string]any{"path": "hidden/secret-diary.md"}, http.StatusOK, nil)
	time.Sleep(2 * time.Second)
	noLeak("private note edited, tagged and moved")

	// Flag on → published; flag off → deleted on the mirror (A19 #8).
	aAdmin.mustDo(http.MethodPatch, "/api/vaults/"+V+"/notes/"+diary.ID, map[string]any{"publish": true}, http.StatusOK, nil)
	eventually(t, wait, "flagged note public", func() string {
		st, body, _ := anonGet(t, b, "/api/public/books/blog/notes/"+diary.ID)
		if st != http.StatusOK || !strings.Contains(body, "more secrets") {
			return fmt.Sprintf("%d %s", st, body)
		}
		return ""
	})
	aAdmin.mustDo(http.MethodPatch, "/api/vaults/"+V+"/notes/"+post.ID, map[string]any{"publish": false}, http.StatusOK, nil)
	eventually(t, wait, "unflagged note gone from the mirror", func() string {
		var n int
		_ = b.query(t, `SELECT count(*) FROM notes WHERE vault_id = $1 AND id = $2`, V, post.ID).Scan(&n)
		st, _, _ := anonGet(t, b, "/api/public/books/blog/notes/"+post.ID)
		if n != 0 || st != http.StatusNotFound {
			return fmt.Sprintf("rows %d, status %d", n, st)
		}
		return ""
	})
	// A Viewer-less anonymous client cannot reach the authed API.
	if st, _, _ := anonGet(t, b, "/api/vaults/"+V+"/notes"); st != http.StatusUnauthorized {
		t.Fatalf("anonymous authed API: %d", st)
	}

	// #9 (purge): home revokes; the publish mirror deletes its copy.
	feds := aAdmin.federations(V)
	aAdmin.mustDo(http.MethodDelete, "/api/vaults/"+V+"/federations/"+feds[0].ID, nil, http.StatusNoContent, nil)
	eventually(t, wait, "mirror purged", func() string {
		var n int
		if err := b.query(t, `SELECT count(*) FROM vaults WHERE id = $1`, V).Scan(&n); err != nil || n != 0 {
			return fmt.Sprintf("vault rows %d %v", n, err)
		}
		return ""
	})
	if st, _, _ := anonGet(t, b, "/api/public/books/blog"); st != http.StatusNotFound {
		t.Fatalf("purged book still public: %d", st)
	}
	var purged int
	if err := b.query(t, `SELECT count(*) FROM audit_log WHERE action = 'mirror.purged'`).Scan(&purged); err != nil || purged != 1 {
		t.Fatalf("purge audited: %d %v", purged, err)
	}
}
