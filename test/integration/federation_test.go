//go:build integration

package integration

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestTwoServerFederation runs two real lumi-server processes (own port,
// root, database and server key each) and walks the SPEC-V3 federation
// lifecycle end to end:
//
//	invite on A → operator join from B → accept → content + control state
//	replicate → concurrent edits on both converge (REST /diff and WS
//	ticket sessions) → member erasure on A propagates via control state →
//	revoke on A → B is told, marks the link severed, and syncing stops.
func TestTwoServerFederation(t *testing.T) {
	admin := postgresAdminURL(t)
	a := startServer(t, "a", createDatabase(t, admin, "lumi_it_a"))
	b := startServer(t, "b", createDatabase(t, admin, "lumi_it_b"))
	const wait = 20 * time.Second

	aAdmin := a.login(t, a.admin, a.pass)
	bAdmin := b.login(t, b.admin, b.pass)

	// --- A: vault (create returns the full view shape) + note --------------
	var vault struct {
		ID         string         `json:"id"`
		Role       string         `json:"role"`
		CanEdit    bool           `json:"can_edit"`
		Head       *int64         `json:"head"`
		Federation map[string]any `json:"federation"`
	}
	aAdmin.mustDo(http.MethodPost, "/api/vaults", map[string]string{"name": "Shared Book"}, http.StatusCreated, &vault)
	if vault.Role != "Admin" || !vault.CanEdit || vault.Head == nil || vault.Federation == nil {
		t.Fatalf("create response lacks view fields: %+v", vault)
	}
	V := vault.ID
	var note struct {
		ID string `json:"id"`
	}
	aAdmin.mustDo(http.MethodPost, "/api/vaults/"+V+"/notes",
		map[string]string{"title": "Chapter", "body": "line one\nline two\n"}, http.StatusCreated, &note)
	N := note.ID
	// The first-boot bootstrap admin is a server admin (panel login).
	if !isServerAdmin(t, a.db, a.admin) || !isServerAdmin(t, b.db, b.admin) {
		t.Fatal("bootstrap admin lacks server_admin")
	}
	// A canvas (SPEC-PARTE2 §6) replicates like any note: raw JSON text.
	const boardJSON = `{"nodes":[{"id":"a","type":"text","text":"hi","x":0,"y":0,"width":100,"height":50}],"edges":[]}`
	var board struct {
		ID   string `json:"id"`
		Kind string `json:"kind"`
	}
	aAdmin.mustDo(http.MethodPost, "/api/vaults/"+V+"/notes",
		map[string]string{"title": "Board", "kind": "canvas", "body": boardJSON}, http.StatusCreated, &board)
	if board.ID != "board.canvas" || board.Kind != "canvas" {
		t.Fatalf("canvas create: %+v", board)
	}

	var roles struct {
		Roles []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"roles"`
	}
	aAdmin.mustDo(http.MethodGet, "/api/vaults/"+V+"/roles", nil, http.StatusOK, &roles)
	editorRole := ""
	for _, r := range roles.Roles {
		if r.Name == "Editor" {
			editorRole = r.ID
		}
	}
	if editorRole == "" {
		t.Fatal("no Editor role")
	}

	// Carol: a local member of A (joins through a vault invite).
	var vinv struct {
		Token string `json:"token"`
	}
	aAdmin.mustDo(http.MethodPost, "/api/vaults/"+V+"/invites", map[string]any{
		"role_id": editorRole, "max_uses": 1, "expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}, http.StatusCreated, &vinv)
	anon := &client{t: t, srv: a}
	anon.mustDo(http.MethodPost, "/api/invites/"+vinv.Token+"/accept",
		map[string]any{"username": "carol", "password": "carol-password-1", "consent": map[string]string{
			"tos_version": "test", "privacy_version": "test", "accepted_at": time.Now().UTC().Format(time.RFC3339),
		}}, http.StatusCreated, nil)
	carol := a.login(t, "carol", "carol-password-1")

	// B's operator is granted Editor on the vault through home's control
	// plane (cross-server member key = username@B).
	bOpKey := b.admin + "@" + b.base
	aAdmin.mustDo(http.MethodPost, "/api/vaults/"+V+"/federated-members",
		map[string]string{"member_key": bOpKey, "role_id": editorRole}, http.StatusCreated, nil)

	// --- federation invite on A → join from B --------------------------------
	var finv struct {
		Token string `json:"token"`
	}
	aAdmin.mustDo(http.MethodPost, "/api/vaults/"+V+"/federation-invites",
		map[string]string{"server_url_hint": b.base}, http.StatusCreated, &finv)

	// B's bootstrap admin is its federation operator (default).
	bAdmin.mustDo(http.MethodPost, "/api/federation/join",
		map[string]string{"home_url": a.base, "token": finv.Token}, http.StatusCreated, nil)
	t.Logf("B joined vault %s homed at %s", V, a.base)

	// --- replication: content + control state ------------------------------
	eventually(t, wait, "note content on B", func() string {
		status, raw := bAdmin.do(http.MethodGet, "/api/vaults/"+V+"/notes/"+N+"/snapshot", nil, nil)
		if status != http.StatusOK {
			return fmt.Sprintf("status %d %s", status, raw)
		}
		if s := bAdmin.snapshot(V, N); s.Text != "line one\nline two\n" {
			return fmt.Sprintf("B text %q", s.Text)
		}
		return ""
	})
	eventually(t, wait, "canvas on B (CRDT and mirrored file)", func() string {
		status, raw := bAdmin.do(http.MethodGet, "/api/vaults/"+V+"/notes/"+board.ID+"/snapshot", nil, nil)
		if status != http.StatusOK {
			return fmt.Sprintf("status %d %s", status, raw)
		}
		if s := bAdmin.snapshot(V, board.ID); s.Text != boardJSON {
			return fmt.Sprintf("B canvas text %q", s.Text)
		}
		files, _ := filepath.Glob(filepath.Join(b.root, "*", "board.canvas"))
		if len(files) != 1 {
			return fmt.Sprintf("B canvas files %v", files)
		}
		if got, _ := os.ReadFile(files[0]); string(got) != boardJSON {
			return fmt.Sprintf("B canvas file %q", got)
		}
		return ""
	})
	aKey := func(user string) string { return user + "@" + a.base }
	eventually(t, wait, "control state on B", func() string {
		seq, keys := replicatedMembers(t, b.db, V)
		if seq == 0 || !contains(keys, bOpKey) || !contains(keys, aKey("carol")) {
			return fmt.Sprintf("seq %d members %v", seq, keys)
		}
		return ""
	})
	// B now authorizes its operator from home's control state.
	eventually(t, wait, "B operator role from control state", func() string {
		var v struct {
			Role       string `json:"role"`
			Federation struct {
				Role   *string `json:"role"`
				Status *string `json:"status"`
			} `json:"federation"`
		}
		bAdmin.mustDo(http.MethodGet, "/api/vaults/"+V, nil, http.StatusOK, &v)
		if v.Role != "Editor" || v.Federation.Role == nil || *v.Federation.Role != "follower" {
			return fmt.Sprintf("%+v", v)
		}
		return ""
	})

	// --- concurrent edits on both servers converge ---------------------------
	converged := func(want ...string) {
		t.Helper()
		eventually(t, wait, "convergence", func() string {
			ta, tb := aAdmin.snapshot(V, N).Text, bAdmin.snapshot(V, N).Text
			if ta != tb {
				return fmt.Sprintf("A %q != B %q", ta, tb)
			}
			for _, w := range want {
				if !strings.Contains(ta, w) {
					return fmt.Sprintf("%q missing %q", ta, w)
				}
			}
			return ""
		})
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); aAdmin.editREST(V, N, func(s string) string { return "A-top (rest)\n" + s }) }()
	go func() { defer wg.Done(); bAdmin.editWS(V, N, func(s string) string { return s + "B-bottom (ws)\n" }) }()
	wg.Wait()
	converged("A-top (rest)", "B-bottom (ws)", "line one")

	wg.Add(2)
	go func() {
		defer wg.Done()
		aAdmin.editWS(V, N, func(s string) string { return strings.Replace(s, "line one", "line one [A ws]", 1) })
	}()
	go func() {
		defer wg.Done()
		bAdmin.editREST(V, N, func(s string) string { return strings.Replace(s, "line two", "line two [B rest]", 1) })
	}()
	wg.Wait()
	converged("line one [A ws]", "line two [B rest]", "A-top (rest)", "B-bottom (ws)")
	final := aAdmin.snapshot(V, N).Text
	t.Logf("converged text on both servers:\n%s", final)

	// --- member erasure on A propagates through control state ---------------
	seqBefore, _ := replicatedMembers(t, b.db, V)
	carol.mustDo(http.MethodDelete, "/api/users/me", map[string]any{"password": "carol-password-1"}, http.StatusNoContent, nil)
	eventually(t, wait, "erasure reaching B", func() string {
		seq, keys := replicatedMembers(t, b.db, V)
		if seq <= seqBefore || contains(keys, aKey("carol")) {
			return fmt.Sprintf("seq %d (before %d) members %v", seq, seqBefore, keys)
		}
		return ""
	})
	seqAfter, _ := replicatedMembers(t, b.db, V)
	// Home sees the follower's ack of the post-erasure document.
	eventually(t, wait, "control ack on A", func() string {
		var feds struct {
			Federations []struct {
				Status       string `json:"status"`
				LastAckedSeq int64  `json:"last_acked_seq"`
			} `json:"federations"`
		}
		aAdmin.mustDo(http.MethodGet, "/api/vaults/"+V+"/federations", nil, http.StatusOK, &feds)
		if len(feds.Federations) != 1 || feds.Federations[0].LastAckedSeq < seqAfter {
			return fmt.Sprintf("%+v (want ack >= %d)", feds, seqAfter)
		}
		return ""
	})
	t.Logf("erasure propagated: control seq %d → %d, carol@A gone from B", seqBefore, seqAfter)

	// --- revoke on A → B learns it and stops syncing --------------------------
	var aFeds struct {
		Federations []struct {
			ID string `json:"id"`
		} `json:"federations"`
	}
	aAdmin.mustDo(http.MethodGet, "/api/vaults/"+V+"/federations", nil, http.StatusOK, &aFeds)
	aAdmin.mustDo(http.MethodDelete, "/api/vaults/"+V+"/federations/"+aFeds.Federations[0].ID, nil, http.StatusNoContent, nil)

	eventually(t, wait, "B marks the link severed", func() string {
		var feds struct {
			Federations []struct {
				Role   string `json:"role"`
				Status string `json:"status"`
			} `json:"federations"`
		}
		status, raw := bAdmin.do(http.MethodGet, "/api/vaults/"+V+"/federations", nil, &feds)
		if status != http.StatusOK {
			return fmt.Sprintf("status %d %s", status, raw)
		}
		if len(feds.Federations) != 1 || feds.Federations[0].Status != "severed" {
			return fmt.Sprintf("%+v", feds)
		}
		return ""
	})
	// Feed-facing view on B reflects it; B's operator falls back to local
	// membership (replica Admin).
	var bView struct {
		Role       string `json:"role"`
		Federation struct {
			Status *string `json:"status"`
		} `json:"federation"`
	}
	bAdmin.mustDo(http.MethodGet, "/api/vaults/"+V, nil, http.StatusOK, &bView)
	if bView.Federation.Status == nil || *bView.Federation.Status != "severed" {
		t.Fatalf("B vault view federation = %+v", bView.Federation)
	}

	// Edits no longer cross in either direction.
	aAdmin.editREST(V, N, func(s string) string { return s + "after revoke on A\n" })
	bAdmin.editREST(V, N, func(s string) string { return s + "after revoke on B\n" })
	time.Sleep(6 * time.Second) // > first relay reconnect backoff
	ta, tb := aAdmin.snapshot(V, N).Text, bAdmin.snapshot(V, N).Text
	if strings.Contains(tb, "after revoke on A") || strings.Contains(ta, "after revoke on B") {
		t.Fatalf("content crossed a revoked link:\nA %q\nB %q", ta, tb)
	}
	if !strings.Contains(ta, "after revoke on A") || !strings.Contains(tb, "after revoke on B") {
		t.Fatalf("local edits lost:\nA %q\nB %q", ta, tb)
	}
	t.Logf("after revoke: A=%q B=%q", lastLine(ta), lastLine(tb))
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return lines[len(lines)-1]
}
