//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	fws "github.com/fasthttp/websocket"
	"github.com/jackc/pgx/v5"

	"github.com/ViniZap4/lumi-server/internal/crdt"
	"github.com/ViniZap4/lumi-server/internal/wsync"
)

const postgresImage = "postgres:16.16-alpine3.24"

// ---- Postgres ---------------------------------------------------------------------

// postgresAdminURL returns a superuser URL: LUMI_TEST_DATABASE_URL, or a
// fresh docker container torn down at cleanup.
func postgresAdminURL(t *testing.T) string {
	t.Helper()
	if u := os.Getenv("LUMI_TEST_DATABASE_URL"); u != "" {
		return u
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("LUMI_TEST_DATABASE_URL unset and docker not available")
	}
	name := fmt.Sprintf("lumi-it-%d", time.Now().UnixNano())
	out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name,
		"-e", "POSTGRES_PASSWORD=lumi", "-e", "POSTGRES_USER=lumi",
		"-p", "127.0.0.1::5432", postgresImage).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run postgres: %v\n%s", err, out)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("docker", "rm", "-f", name).CombinedOutput(); err != nil {
			t.Logf("docker rm %s: %v %s", name, err, out)
		}
	})
	out, err = exec.Command("docker", "port", name, "5432/tcp").Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	hostPort := strings.TrimSpace(strings.Split(string(out), "\n")[0])
	admin := "postgres://lumi:lumi@" + hostPort + "/postgres?sslmode=disable"
	deadline := time.Now().Add(60 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, err := pgx.Connect(ctx, admin)
		if err == nil {
			err = conn.Ping(ctx)
			_ = conn.Close(ctx)
		}
		cancel()
		if err == nil {
			return admin
		}
		if time.Now().After(deadline) {
			t.Fatalf("postgres never became ready: %v", err)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// createDatabase makes a fresh database and returns its URL.
func createDatabase(t *testing.T, adminURL, name string) string {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	ident := pgx.Identifier{name}.Sanitize()
	if _, err := conn.Exec(ctx, "DROP DATABASE IF EXISTS "+ident+" WITH (FORCE)"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, "CREATE DATABASE "+ident); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), adminURL)
		if err != nil {
			return
		}
		defer c.Close(context.Background())
		_, _ = c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+ident+" WITH (FORCE)")
	})
	u, err := url.Parse(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	return u.String()
}

// ---- server processes ---------------------------------------------------------------

func moduleRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Dir(strings.TrimSpace(string(out)))
}

var (
	buildOnce sync.Once
	buildPath string
	buildErr  error
)

// serverBinary builds cmd/lumi-server once per test binary.
func serverBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "lumi-it-bin-")
		if err != nil {
			buildErr = err
			return
		}
		buildPath = filepath.Join(dir, "lumi-server")
		cmd := exec.Command("go", "build", "-o", buildPath, "./cmd/lumi-server")
		cmd.Dir = moduleRoot(t)
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("go build: %v\n%s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatal(buildErr)
	}
	return buildPath
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

type server struct {
	name    string
	base    string // http://127.0.0.1:port
	logPath string
	cmd     *exec.Cmd
	db      string
	admin   string // bootstrap admin username
	pass    string
	root    string // LUMI_ROOT
}

func startServer(t *testing.T, name, dbURL string) *server {
	t.Helper()
	port := freePort(t)
	root := t.TempDir()
	logPath := filepath.Join(t.TempDir(), name+".log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	s := &server{
		name: name, base: fmt.Sprintf("http://127.0.0.1:%d", port), logPath: logPath, db: dbURL,
		admin: name + "admin", pass: "integration-pass-" + name, root: root,
	}
	cmd := exec.Command(serverBinary(t))
	cmd.Env = append(os.Environ(),
		"LUMI_DATABASE_URL="+dbURL,
		"LUMI_ROOT="+root,
		fmt.Sprintf("LUMI_PORT=%d", port),
		"LUMI_BIND_ADDR=127.0.0.1",
		"LUMI_AUTO_MIGRATE=true",
		"LUMI_MIGRATIONS_DIR="+filepath.Join(moduleRoot(t), "migrations"),
		"LUMI_ADMIN_USERNAME="+s.admin,
		"LUMI_ADMIN_PASSWORD="+s.pass,
		"LUMI_PUBLIC_BASE_URL="+s.base,
		"LUMI_SERVER_NAME="+name,
		"LUMI_REGISTRATION=invite-only",
		"LUMI_LOG_LEVEL=debug",
		// Test-only federation SSRF escape hatches: loopback over http.
		"LUMI_FEDERATION_ALLOW_HTTP=true",
		"LUMI_FEDERATION_ALLOWED_CIDRS=127.0.0.0/8",
		"LUMI_TOS_VERSION=", "LUMI_PRIVACY_VERSION=",
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	s.cmd = cmd
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait(); logFile.Close() }()
	t.Cleanup(func() {
		_ = cmd.Process.Signal(os.Interrupt)
		select {
		case <-exited:
		case <-time.After(15 * time.Second):
			_ = cmd.Process.Kill()
			<-exited
		}
		if t.Failed() {
			if b, err := os.ReadFile(logPath); err == nil {
				t.Logf("---- %s log (tail) ----\n%s", name, tail(string(b), 6000))
			}
		}
	})
	deadline := time.Now().Add(60 * time.Second)
	for {
		select {
		case err := <-exited:
			b, _ := os.ReadFile(logPath)
			t.Fatalf("%s exited during startup: %v\n%s", name, err, b)
		default:
		}
		resp, err := http.Get(s.base + "/readyz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return s
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s not ready", name)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

func (s *server) logContains(sub string) bool {
	b, _ := os.ReadFile(s.logPath)
	return bytes.Contains(b, []byte(sub))
}

// ---- HTTP client -------------------------------------------------------------------------

type client struct {
	t     *testing.T
	srv   *server
	token string
}

func (s *server) login(t *testing.T, user, pass string) *client {
	t.Helper()
	c := &client{t: t, srv: s}
	var out struct {
		Token string `json:"token"`
	}
	c.mustDo(http.MethodPost, "/api/auth/login", map[string]string{"username": user, "password": pass}, http.StatusOK, &out)
	c.token = out.Token
	return c
}

// do sends a JSON request and decodes the JSON answer into out (if non-nil).
func (c *client) do(method, path string, body, out any) (int, []byte) {
	c.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.srv.base+path, rdr)
	if err != nil {
		c.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("X-Lumi-Token", c.token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s %s: %v", c.srv.name, method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode < 300 && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			c.t.Fatalf("%s %s %s: decode %s: %v", c.srv.name, method, path, raw, err)
		}
	}
	return resp.StatusCode, raw
}

func (c *client) mustDo(method, path string, body any, want int, out any) []byte {
	c.t.Helper()
	status, raw := c.do(method, path, body, out)
	if status != want {
		c.t.Fatalf("%s %s %s: status %d, want %d: %s", c.srv.name, method, path, status, want, raw)
	}
	return raw
}

type snapshot struct {
	Text  string `json:"text"`
	State string `json:"state"`
}

func (c *client) snapshot(vault, note string) snapshot {
	c.t.Helper()
	var s snapshot
	c.mustDo(http.MethodGet, "/api/vaults/"+vault+"/notes/"+note+"/snapshot", nil, http.StatusOK, &s)
	return s
}

// editREST applies edit(text) through the opaque-editor 3-way /diff.
func (c *client) editREST(vault, note string, edit func(string) string) {
	c.t.Helper()
	s := c.snapshot(vault, note)
	var out struct {
		Text  string `json:"text"`
		State string `json:"state"`
	}
	c.mustDo(http.MethodPost, "/api/vaults/"+vault+"/notes/"+note+"/diff",
		map[string]string{"text": edit(s.Text), "base_state": s.State, "origin": "tui-diff"}, http.StatusOK, &out)
	if out.State == "" {
		c.t.Errorf("%s: /diff response lacks state", c.srv.name)
	}
}

// editWS applies edit(text) as a live Yjs client: mint a ws-ticket, run the
// y-protocols handshake, send one update.
func (c *client) editWS(vault, note string, edit func(string) string) {
	c.t.Helper()
	var tk struct {
		Ticket    string `json:"ticket"`
		ExpiresAt string `json:"expires_at"`
	}
	c.mustDo(http.MethodPost, "/api/vaults/"+vault+"/notes/"+note+"/ws-ticket", nil, http.StatusCreated, &tk)
	if raw, err := base64.RawURLEncoding.DecodeString(tk.Ticket); err != nil || len(raw) < 32 {
		c.t.Fatalf("bad ticket %q", tk.Ticket)
	}
	wsURL := "ws" + strings.TrimPrefix(c.srv.base, "http") + "/api/vaults/" + vault + "/notes/" + note + "/sync?ticket=" + tk.Ticket
	conn, _, err := (&fws.Dialer{HandshakeTimeout: 5 * time.Second}).Dial(wsURL, nil)
	if err != nil {
		c.t.Fatalf("%s ws dial: %v", c.srv.name, err)
	}
	defer conn.Close()

	doc := crdt.NewDoc()
	defer doc.Close()
	sv, _ := doc.StateVectorV1()
	if err := conn.WriteMessage(fws.BinaryMessage, wsync.EncodeSyncStep1(sv)); err != nil {
		c.t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	for synced := false; !synced; {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			var ce *fws.CloseError
			if errors.As(err, &ce) {
				c.t.Fatalf("%s ws closed %d %q", c.srv.name, ce.Code, ce.Text)
			}
			c.t.Fatalf("%s ws read: %v", c.srv.name, err)
		}
		m, err := wsync.DecodeMessage(msg)
		if err != nil || m.Type != wsync.MessageSync {
			continue
		}
		switch m.SyncSub {
		case wsync.SyncStep2:
			if err := doc.ApplyUpdate(m.Body); err != nil {
				c.t.Fatal(err)
			}
			synced = true
		case wsync.SyncUpdate:
			_ = doc.ApplyUpdate(m.Body)
		}
	}
	text, _ := doc.Text()
	update, err := doc.ApplyTextDiff(edit(text), "it")
	if err != nil {
		c.t.Fatal(err)
	}
	if err := conn.WriteMessage(fws.BinaryMessage, wsync.EncodeSyncUpdate(update)); err != nil {
		c.t.Fatal(err)
	}
	// Give the server a moment to apply before closing.
	time.Sleep(200 * time.Millisecond)
	_ = conn.WriteControl(fws.CloseMessage, fws.FormatCloseMessage(fws.CloseNormalClosure, ""), time.Now().Add(time.Second))
}

// eventually polls cond until it returns "" or the deadline passes.
func eventually(t *testing.T, timeout time.Duration, what string, cond func() string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	for {
		if last = cond(); last == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s: %s", what, last)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// replicatedMembers reads the follower's replicated control document.
func replicatedMembers(t *testing.T, dbURL, vault string) (int64, []string) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	var seq int64
	var raw []byte
	err = conn.QueryRow(ctx, `SELECT seq, state FROM replicated_control_state WHERE vault_id = $1`, vault).Scan(&seq, &raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Members []struct {
			Key string `json:"key"`
		} `json:"members"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(doc.Members))
	for _, m := range doc.Members {
		keys = append(keys, m.Key)
	}
	return seq, keys
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// isServerAdmin reads users.server_admin of username (migration 0009).
func isServerAdmin(t *testing.T, dbURL, username string) bool {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	var ok bool
	if err := conn.QueryRow(ctx, `SELECT server_admin FROM users WHERE username = $1`, username).Scan(&ok); err != nil {
		t.Fatal(err)
	}
	return ok
}
