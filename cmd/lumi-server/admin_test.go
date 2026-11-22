package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"strings"
	"testing"
	"time"

	"github.com/ViniZap4/lumi-server/internal/admin"
)

func TestAdminListenerRefusesPublicAddress(t *testing.T) {
	pub := config{bindAddr: "0.0.0.0", port: 8080}
	for _, addr := range []string{"0.0.0.0:8080", "127.0.0.1:8080", "localhost:8080", ":8080", "[::1]:8080"} {
		t.Setenv("LUMI_ADMIN_ADDR", addr)
		if _, err := loadAdminConfig(pub); err == nil || !strings.Contains(err.Error(), "must differ") {
			t.Errorf("%s vs 0.0.0.0:8080: %v", addr, err)
		}
	}
	loop := config{bindAddr: "127.0.0.1", port: 8080}
	t.Setenv("LUMI_ADMIN_ADDR", "localhost:8080")
	if _, err := loadAdminConfig(loop); err == nil {
		t.Error("localhost vs 127.0.0.1 on the same port accepted")
	}
	t.Setenv("LUMI_ADMIN_ADDR", "0.0.0.0:8081")
	t.Setenv("LUMI_ADMIN_TRUSTED_PROXIES", "172.16.0.0/12")
	ac, err := loadAdminConfig(pub)
	if err != nil || ac.addr != "0.0.0.0:8081" || len(ac.trustedProxies) != 1 {
		t.Fatalf("valid config: %+v %v", ac, err)
	}
	t.Setenv("LUMI_ADMIN_TRUSTED_PROXIES", "not-a-cidr")
	if _, err := loadAdminConfig(pub); err == nil {
		t.Error("bad proxy list accepted")
	}
	t.Setenv("LUMI_ADMIN_TRUSTED_PROXIES", "")
	t.Setenv("LUMI_ADMIN_ADDR", "8081")
	if _, err := loadAdminConfig(pub); err == nil {
		t.Error("port without host accepted")
	}
	t.Setenv("LUMI_ADMIN_ADDR", "")
	if ac, err := loadAdminConfig(pub); err != nil || ac.addr != "" {
		t.Fatalf("off: %+v %v", ac, err)
	}
}

func TestCLIParsing(t *testing.T) {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "")
	force := fs.Bool("delete-owned-vaults", false, "")
	pos, err := parse(fs, []string{"--yes", "alice", "--delete-owned-vaults"}, 1)
	if err != nil || pos[0] != "alice" || !*yes || !*force {
		t.Fatalf("parse: %v %v", pos, err)
	}
	if _, err := parse(flag.NewFlagSet("y", flag.ContinueOnError), []string{"a", "b"}, 1); !errors.Is(err, errUsage) {
		t.Fatalf("extra positional: %v", err)
	}
	if _, err := parse(flag.NewFlagSet("z", flag.ContinueOnError), []string{"--nope"}, 0); !errors.Is(err, errUsage) {
		t.Fatalf("unknown flag: %v", err)
	}
	for in, want := range map[string]time.Duration{"30d": 30 * 24 * time.Hour, "720h": 720 * time.Hour, "90m": 90 * time.Minute} {
		if got, err := parseTTL(in); err != nil || got != want {
			t.Errorf("parseTTL(%q) = %v %v", in, got, err)
		}
	}
	if _, err := parseTTL("soon"); err == nil {
		t.Error("parseTTL accepted garbage")
	}
}

func TestCLIUsageAndConfirm(t *testing.T) {
	var out, errb bytes.Buffer
	opened := false
	e := &cliEnv{out: &out, err: &errb, in: strings.NewReader(""),
		open: func(context.Context) (*admin.Service, func(), error) {
			opened = true
			return nil, nil, errors.New("no db")
		}}
	for _, args := range [][]string{{"token"}, {"token", "mint"}, {"user"}, {"user", "fly", "x"}} {
		if code := e.run(context.Background(), args); code != exitUsage {
			t.Errorf("%v: exit %d", args, code)
		}
	}
	if opened {
		t.Fatal("usage errors opened the database")
	}
	if !isAdminCommand("token") || isAdminCommand("migrate") {
		t.Fatal("isAdminCommand")
	}

	// Destructive commands need --yes when stdin is not a terminal.
	if err := e.confirm(false, "user alice", "alice"); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("non-terminal confirm: %v", err)
	}
	e.terminal = true
	e.in = strings.NewReader("bob\n")
	if err := e.confirm(false, "user alice", "alice"); err == nil {
		t.Fatal("wrong name confirmed")
	}
	e.in = strings.NewReader("alice\n")
	if err := e.confirm(false, "user alice", "alice"); err != nil {
		t.Fatalf("right name: %v", err)
	}

	// Passwords: piped with --password-stdin, never from a non-terminal prompt.
	e.terminal = false
	e.in = strings.NewReader("s3cret pass\r\n")
	if pw, err := e.readNewPassword(true, "alice"); err != nil || pw != "s3cret pass" {
		t.Fatalf("stdin password %q %v", pw, err)
	}
	if _, err := e.readNewPassword(false, "alice"); err == nil {
		t.Fatal("prompted without a terminal")
	}
	e.terminal = true
	answers := []string{"one pass 1", "two pass 2"}
	e.readPass = func(string) (string, error) { a := answers[0]; answers = answers[1:]; return a, nil }
	if _, err := e.readNewPassword(false, "alice"); err == nil {
		t.Fatal("mismatched passwords accepted")
	}
}
