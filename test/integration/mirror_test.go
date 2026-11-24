//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	fws "github.com/fasthttp/websocket"
	"github.com/jackc/pgx/v5"

	"github.com/ViniZap4/lumi-server/internal/crdt"
	"github.com/ViniZap4/lumi-server/internal/federation"
	"github.com/ViniZap4/lumi-server/internal/wsync"
)

// cli runs `lumi-server <args>` against a server's database and root, as
// an operator would on that host.
func (s *server) cli(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command(serverBinary(t), args...)
	cmd.Env = append(os.Environ(),
		"LUMI_DATABASE_URL="+s.db, "LUMI_ROOT="+s.root, "LUMI_PUBLIC_BASE_URL="+s.base,
		"LUMI_MIGRATIONS_DIR="+moduleRoot(t)+"/migrations")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s: lumi-server %v: %v\n%s", s.name, args, err, out)
	}
	return string(out)
}

func (s *server) query(t *testing.T, q string, args ...any) pgx.Row {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, s.db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	return conn.QueryRow(ctx, q, args...)
}

type fedItem struct {
	ID             string  `json:"id"`
	Role           string  `json:"role"`
	Mode           string  `json:"mode"`
	Status         string  `json:"status"`
	LagSeq         int64   `json:"lag_seq"`
	PendingDeletes int64   `json:"pending_deletes"`
	MirrorAckedSeq int64   `json:"mirror_acked_seq"`
	LastContactAt  *string `json:"last_contact_at"`
}

func (c *client) federations(vault string) []fedItem {
	c.t.Helper()
	var out struct {
		Federations []fedItem `json:"federations"`
	}
	c.mustDo(http.MethodGet, "/api/vaults/"+vault+"/federations", nil, http.StatusOK, &out)
	return out.Federations
}

type contentResp struct {
	Body        string         `json:"body"`
	Frontmatter map[string]any `json:"frontmatter"`
}

func (c *client) content(vault, note string) (int, contentResp) {
	c.t.Helper()
	var out contentResp
	status, _ := c.do(http.MethodGet, "/api/vaults/"+vault+"/notes/"+note+"/content", nil, &out)
	return status, out
}

func errorOf(raw []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(raw, &e)
	return e.Error
}

// TestTwoServerMirror walks the one-way mirror lifecycle between two real
// servers (docs/SPEC-ESPELHO-SELADO.md §A19): v1 accept refused (#11),
// setup and backfill with frontmatter (#1, #7), read-only clamp (#2),
// live updates, deletes and lineage changes (#1, #6), an offline mirror
// catching up on deletes (#4), a forged content frame from the mirror's
// key (#3), revoke keeping a frozen copy (#9 keep) and promotion (#10).
func TestTwoServerMirror(t *testing.T) {
	adminURL := postgresAdminURL(t)
	a := startServer(t, "a", createDatabase(t, adminURL, "lumi_it_mirror_a"))
	b := startServer(t, "b", createDatabase(t, adminURL, "lumi_it_mirror_b"))
	const wait = 30 * time.Second

	aAdmin := a.login(t, a.admin, a.pass)
	bAdmin := b.login(t, b.admin, b.pass)

	var vault struct {
		ID string `json:"id"`
	}
	aAdmin.mustDo(http.MethodPost, "/api/vaults", map[string]string{"name": "Mirrored Book"}, http.StatusCreated, &vault)
	V := vault.ID
	var note struct {
		ID string `json:"id"`
	}
	aAdmin.mustDo(http.MethodPost, "/api/vaults/"+V+"/notes",
		map[string]any{"title": "Chapter", "body": "first line\n", "tags": []string{"lgpd", "backup"}}, http.StatusCreated, &note)
	N := note.ID
	_, homeContent := aAdmin.content(V, N)
	homeCreated, _ := homeContent.Frontmatter["created_at"].(string)
	aAdmin.mustDo(http.MethodPost, "/api/vaults/"+V+"/notes", map[string]any{"title": "Appendix", "body": "appendix\n"}, http.StatusCreated, nil)

	// Home grants B's operator Admin: on the mirror it is clamped to read.
	var roles struct {
		Roles []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"roles"`
	}
	aAdmin.mustDo(http.MethodGet, "/api/vaults/"+V+"/roles", nil, http.StatusOK, &roles)
	adminRole := ""
	for _, r := range roles.Roles {
		if r.Name == "Admin" {
			adminRole = r.ID
		}
	}
	aAdmin.mustDo(http.MethodPost, "/api/vaults/"+V+"/federated-members",
		map[string]string{"member_key": b.admin + "@" + b.base, "role_id": adminRole}, http.StatusCreated, nil)

	var inv struct {
		Token       string `json:"token"`
		Mode        string `json:"mode"`
		SeverPolicy string `json:"sever_policy"`
	}
	aAdmin.mustDo(http.MethodPost, "/api/vaults/"+V+"/federation-invites",
		map[string]string{"server_url_hint": b.base, "mode": "mirror"}, http.StatusCreated, &inv)
	if inv.Mode != "mirror" || inv.SeverPolicy != "keep" {
		t.Fatalf("invite %+v", inv)
	}

	// #11: a v1 follower (v1 signature, no mode) is refused and the
	// invite survives.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	anonA := &client{t: t, srv: a}
	status, raw := anonA.do(http.MethodPost, "/api/federation/accept", map[string]string{
		"token": inv.Token, "follower_url": b.base, "follower_pubkey": hex.EncodeToString(pub),
		"signature": hex.EncodeToString(ed25519.Sign(priv, federation.AcceptMessage(inv.Token, b.base))),
	}, nil)
	if status != http.StatusConflict || errorOf(raw) != "mirror_unsupported" {
		t.Fatalf("v1 accept of a mirror invite: %d %s", status, raw)
	}

	bAdmin.mustDo(http.MethodPost, "/api/federation/join",
		map[string]string{"home_url": a.base, "token": inv.Token, "mode": "mirror"}, http.StatusCreated, nil)

	// #1, #7: backfill with content and frontmatter.
	eventually(t, wait, "backfill with frontmatter on B", func() string {
		status, c := bAdmin.content(V, N)
		if status != http.StatusOK {
			return fmt.Sprintf("status %d", status)
		}
		tags, _ := c.Frontmatter["tags"].([]any)
		if c.Body != "first line\n" || len(tags) != 2 || c.Frontmatter["created_at"] != homeCreated {
			return fmt.Sprintf("content %+v (want created_at %s)", c, homeCreated)
		}
		return ""
	})
	var bView struct {
		Mirror     bool `json:"mirror"`
		CanEdit    bool `json:"can_edit"`
		Federation struct {
			Role    *string `json:"role"`
			HomeURL *string `json:"home_url"`
		} `json:"federation"`
	}
	eventually(t, wait, "B sees a read-only mirror", func() string {
		bAdmin.mustDo(http.MethodGet, "/api/vaults/"+V, nil, http.StatusOK, &bView)
		if !bView.Mirror || bView.CanEdit || bView.Federation.Role == nil || *bView.Federation.Role != "mirror" ||
			bView.Federation.HomeURL == nil || *bView.Federation.HomeURL != a.base {
			return fmt.Sprintf("%+v", bView)
		}
		return ""
	})

	// #2: writes on the mirror are refused.
	readOnly := func(when string) {
		t.Helper()
		for _, w := range []struct {
			method, path string
			body         any
		}{
			{http.MethodPatch, "/api/vaults/" + V + "/notes/" + N, map[string]string{"body": "mirror edit"}},
			{http.MethodPost, "/api/vaults/" + V + "/notes", map[string]string{"title": "New"}},
			{http.MethodDelete, "/api/vaults/" + V + "/notes/" + N, nil},
			{http.MethodPost, "/api/vaults/" + V + "/notes/" + N + "/ws-ticket", nil},
			{http.MethodPatch, "/api/vaults/" + V, map[string]string{"name": "renamed"}},
		} {
			status, raw := bAdmin.do(w.method, w.path, w.body, nil)
			if status != http.StatusForbidden || errorOf(raw) != "mirror_read_only" {
				t.Fatalf("%s: %s %s on the mirror: %d %s", when, w.method, w.path, status, raw)
			}
		}
	}
	readOnly("live mirror")

	// #1: live update.
	aAdmin.editREST(V, N, func(s string) string { return s + "second line\n" })
	eventually(t, wait, "live edit on B", func() string {
		if s := bAdmin.snapshot(V, N); s.Text != "first line\nsecond line\n" {
			return fmt.Sprintf("B text %q", s.Text)
		}
		return ""
	})

	// #6: delete and recreate at home → the mirror follows the new lineage.
	var oldNote, newNote struct {
		CRDTEpoch string `json:"crdt_epoch"`
	}
	aAdmin.mustDo(http.MethodGet, "/api/vaults/"+V+"/notes/appendix", nil, http.StatusOK, &oldNote)
	aAdmin.mustDo(http.MethodDelete, "/api/vaults/"+V+"/notes/appendix", nil, http.StatusNoContent, nil)
	aAdmin.mustDo(http.MethodPost, "/api/vaults/"+V+"/notes", map[string]any{"title": "Appendix", "body": "rewritten\n"}, http.StatusCreated, &newNote)
	if newNote.CRDTEpoch == oldNote.CRDTEpoch {
		t.Fatal("recreate kept the epoch")
	}
	eventually(t, wait, "new lineage on B", func() string {
		var n struct {
			CRDTEpoch string `json:"crdt_epoch"`
		}
		if status, _ := bAdmin.do(http.MethodGet, "/api/vaults/"+V+"/notes/appendix", nil, &n); status != http.StatusOK || n.CRDTEpoch != newNote.CRDTEpoch {
			return fmt.Sprintf("B epoch %q, want %q", n.CRDTEpoch, newNote.CRDTEpoch)
		}
		if s := bAdmin.snapshot(V, "appendix"); s.Text != "rewritten\n" {
			return fmt.Sprintf("B text %q", s.Text)
		}
		return ""
	})
	// Home sees the mirror catch up: acked, no lag, no pending delete.
	eventually(t, wait, "mirror acks on A", func() string {
		feds := aAdmin.federations(V)
		if len(feds) != 1 || feds[0].Mode != "mirror" || feds[0].LagSeq != 0 || feds[0].PendingDeletes != 0 || feds[0].MirrorAckedSeq == 0 {
			return fmt.Sprintf("%+v", feds)
		}
		return ""
	})

	// #4: the mirror goes offline (operator pause on B), home deletes.
	bFeds := bAdmin.federations(V)
	if len(bFeds) != 1 || bFeds[0].Role != "follower" || bFeds[0].Mode != "mirror" {
		t.Fatalf("B federations %+v", bFeds)
	}
	bFedID := bFeds[0].ID
	b.cli(t, "mirror", "pause", bFedID)
	eventually(t, wait, "B link down", func() string {
		if a.logContains(`"message":"federation: relay session ended"`) {
			return ""
		}
		return "still linked"
	})
	aAdmin.mustDo(http.MethodDelete, "/api/vaults/"+V+"/notes/appendix", nil, http.StatusNoContent, nil)
	eventually(t, wait, "pending delete visible on A", func() string {
		if feds := aAdmin.federations(V); len(feds) != 1 || feds[0].PendingDeletes != 1 {
			return fmt.Sprintf("%+v", feds)
		}
		return ""
	})
	if status, _ := bAdmin.do(http.MethodGet, "/api/vaults/"+V+"/notes/appendix", nil, nil); status != http.StatusOK {
		t.Fatalf("paused mirror lost the note early: %d", status)
	}

	// #3: someone holding the mirror's server key forges a content frame.
	forgeFromMirror(t, a, b, aAdmin, V, N)
	if s := aAdmin.snapshot(V, N); strings.Contains(s.Text, "forged") {
		t.Fatalf("forged mirror frame changed home: %q", s.Text)
	}
	eventually(t, wait, "mirror violation audited on A", func() string {
		var violations int
		if err := a.query(t, `SELECT count(*) FROM audit_log WHERE action = 'federation.mirror_violation' AND vault_id = $1`, V).Scan(&violations); err != nil || violations != 1 {
			return fmt.Sprintf("%d %v", violations, err)
		}
		return ""
	})

	// Back online: the delete made while away reaches the mirror.
	b.cli(t, "mirror", "resume", bFedID)
	eventually(t, wait, "offline delete reaches B", func() string {
		if status, _ := bAdmin.do(http.MethodGet, "/api/vaults/"+V+"/notes/appendix", nil, nil); status != http.StatusNotFound {
			return fmt.Sprintf("status %d", status)
		}
		return ""
	})
	eventually(t, wait, "pending deletes drained on A", func() string {
		if feds := aAdmin.federations(V); len(feds) != 1 || feds[0].PendingDeletes != 0 || feds[0].LagSeq != 0 {
			return fmt.Sprintf("%+v", feds)
		}
		return ""
	})
	statusOut := b.cli(t, "mirror", "status", bFedID)
	if !strings.Contains(statusOut, "home seq applied") {
		t.Fatalf("mirror status output:\n%s", statusOut)
	}

	// #9 (keep): home revokes; the mirror keeps a frozen read-only copy.
	aFeds := aAdmin.federations(V)
	aAdmin.mustDo(http.MethodDelete, "/api/vaults/"+V+"/federations/"+aFeds[0].ID, nil, http.StatusNoContent, nil)
	eventually(t, wait, "B severed", func() string {
		var st string
		if err := b.query(t, `SELECT status FROM vault_federations WHERE vault_id = $1`, V).Scan(&st); err != nil || st != "severed" {
			return fmt.Sprintf("status %q %v", st, err)
		}
		return ""
	})
	time.Sleep(time.Second)
	eventually(t, wait, "frozen copy readable", func() string {
		status, c := bAdmin.content(V, N)
		if status != http.StatusOK || c.Body != "first line\nsecond line\n" {
			return fmt.Sprintf("%d %+v", status, c)
		}
		return ""
	})
	eventually(t, 45*time.Second, "frozen copy still read-only", func() string {
		bAdmin.mustDo(http.MethodGet, "/api/vaults/"+V, nil, http.StatusOK, &bView)
		if !bView.Mirror || bView.CanEdit {
			return fmt.Sprintf("%+v", bView)
		}
		return ""
	})
	readOnly("revoked mirror")

	// #10: promotion (CLI only) makes the copy an independent home.
	out := b.cli(t, "mirror", "promote", V, "--confirm")
	if !strings.Contains(out, "promoted mirror") {
		t.Fatalf("promote output:\n%s", out)
	}
	eventually(t, 60*time.Second, "promoted copy writable", func() string {
		status, raw := bAdmin.do(http.MethodPatch, "/api/vaults/"+V+"/notes/"+N, map[string]string{"body": "after promotion\n"}, nil)
		if status != http.StatusOK {
			return fmt.Sprintf("%d %s", status, raw)
		}
		return ""
	})
	bAdmin.mustDo(http.MethodGet, "/api/vaults/"+V, nil, http.StatusOK, &bView)
	if bView.Mirror || !bView.CanEdit {
		t.Fatalf("promoted view %+v", bView)
	}
	var promoted int
	if err := b.query(t, `SELECT count(*) FROM audit_log WHERE action = 'mirror.promote' AND vault_id = $1`, V).Scan(&promoted); err != nil || promoted != 1 {
		t.Fatalf("promotion audited: %d %v", promoted, err)
	}
}

// forgeFromMirror dials home's relay with the mirror server's own key and
// sends a content update: home must close the link and change nothing.
func forgeFromMirror(t *testing.T, a, b *server, aAdmin *client, vault, note string) {
	t.Helper()
	var privKey []byte
	if err := b.query(t, `SELECT private_key FROM server_keys WHERE id = 1`).Scan(&privKey); err != nil {
		t.Fatal(err)
	}
	priv := ed25519.PrivateKey(privKey)
	anon := &client{t: t, srv: a}
	var ch struct {
		Nonce string `json:"nonce"`
	}
	anon.mustDo(http.MethodPost, "/api/federation/sync-challenge", map[string]string{"vault_id": vault, "peer_url": b.base}, http.StatusOK, &ch)
	sig := ed25519.Sign(priv, federation.SyncAuthMessage(ch.Nonce, vault, b.base))
	q := url.Values{"peer_url": {b.base}, "nonce": {ch.Nonce}, "sig": {hex.EncodeToString(sig)}, "proto": {"2"}}
	wsURL := "ws" + strings.TrimPrefix(a.base, "http") + "/api/federation/vaults/" + vault + "/sync?" + q.Encode()
	conn, _, err := (&fws.Dialer{HandshakeTimeout: 5 * time.Second}).Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("forged relay dial: %v", err)
	}
	defer conn.Close()

	s := aAdmin.snapshot(vault, note)
	state, _ := base64.StdEncoding.DecodeString(s.State)
	doc, err := crdt.LoadDoc(state)
	if err != nil {
		t.Fatal(err)
	}
	defer doc.Close()
	update, err := doc.ApplyTextDiff(s.Text+"forged by the mirror\n", "evil")
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.WriteMessage(fws.BinaryMessage, federation.EncodeNoteSync(note, wsync.EncodeSyncUpdate(update))); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			return // home closed the link
		}
	}
}
