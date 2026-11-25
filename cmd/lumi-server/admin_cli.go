package main

// CLI subcommands of docs/ADMIN.md. They call the same admin.Service as
// the admin API: same rules, same refusals.

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
	"golang.org/x/term"

	"github.com/ViniZap4/lumi-server/internal/admin"
	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/storage/fs"
	"github.com/ViniZap4/lumi-server/internal/storage/pg"
	"github.com/ViniZap4/lumi-server/internal/users"
)

// isAdminCommand reports whether args[0] is an admin CLI subcommand.
func isAdminCommand(cmd string) bool {
	switch cmd {
	case "token", "status", "user", "session", "vault", "federation", "audit", "admin", "mirror", "publish":
		return true
	}
	return false
}

const adminUsage = `Administration (docs/ADMIN.md; same rules as the admin API):
  lumi-server status [--json]
  lumi-server token create <name> [--ttl 30d]     print a new admin token (shown once)
  lumi-server token list [--json]
  lumi-server token revoke <id>                   also ends an admin session (lps_) by id
  lumi-server admin list [--json]                 server admins (panel password login)
  lumi-server admin grant|revoke <user>           set or clear the server_admin flag
  lumi-server user list [--json]
  lumi-server user show <user> [--json]
  lumi-server user create <username> [--display-name s] [--password-stdin]
  lumi-server user password <user> [--password-stdin]   ends the user's sessions
  lumi-server user disable|enable|unlock <user>
  lumi-server user delete <user> [--delete-owned-vaults] [--yes]   LGPD erasure
  lumi-server session list [--user u] [--json]
  lumi-server session revoke <id>
  lumi-server vault list [--user u] [--json]
  lumi-server vault show <vault> [--json]
  lumi-server vault delete <vault> [--yes]
  lumi-server federation list [--vault v] [--mode replica|mirror] [--json]
  lumi-server federation status <id> [--json]
  lumi-server federation revoke <id>
  lumi-server federation pause|resume <id>        stop/restart a link without revoking it
  lumi-server mirror list [--vault v] [--json]    one-way mirror links (both sides)
  lumi-server mirror status <id> [--json]         lag, pending deletes, last contact
  lumi-server mirror resync <id>                  mirror side: forget progress, full pass
  lumi-server mirror pause|resume <id>
  lumi-server mirror promote <vault> --confirm    mirror becomes an independent home (CLI only)
  lumi-server publish enable <vault> --slug s [--robots noindex|index]   serve a publish mirror at /p/<slug>
  lumi-server publish disable <vault>
  lumi-server publish list [--json]               (anonymous endpoints also need LUMI_PUBLISH_ENABLED=true)
  lumi-server audit [--limit 50] [--before id] [--scope all|admin] [--user u] [--vault v] [--json]
<user> is a username or id; <vault> a slug or id.`

// cliEnv is the CLI's world, swappable in tests.
type cliEnv struct {
	in       io.Reader
	out, err io.Writer
	terminal bool // stdin is an interactive terminal
	readPass func(prompt string) (string, error)
	open     func(ctx context.Context) (*admin.Service, func(), error)
}

func adminCLI(args []string) int {
	stdinFD := int(os.Stdin.Fd())
	env := &cliEnv{
		in: os.Stdin, out: os.Stdout, err: os.Stderr,
		terminal: term.IsTerminal(stdinFD),
		readPass: func(prompt string) (string, error) {
			fmt.Fprint(os.Stderr, prompt)
			b, err := term.ReadPassword(stdinFD)
			fmt.Fprintln(os.Stderr)
			return string(b), err
		},
		open: openCLIAdmin,
	}
	return env.run(context.Background(), args)
}

func openCLIAdmin(ctx context.Context) (*admin.Service, func(), error) {
	_ = godotenv.Load()
	cfg, err := loadConfig()
	if err != nil {
		return nil, nil, fmt.Errorf("config: %w", err)
	}
	zlog := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
		Level(zerolog.WarnLevel).With().Timestamp().Logger()
	pool, err := pg.New(ctx, cfg.databaseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("postgres: %w", err)
	}
	fsMgr, err := fs.NewManager(cfg.root)
	if err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("fs manager: %w", err)
	}
	svc, err := buildCLIAdmin(ctx, cfg, zlog, pool, fsMgr)
	if err != nil {
		pool.Close()
		return nil, nil, err
	}
	return svc, pool.Close, nil
}

var errUsage = errors.New("usage")

func (e *cliEnv) run(ctx context.Context, args []string) int {
	err := e.dispatch(ctx, args)
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, errUsage):
		fmt.Fprintln(e.err, adminUsage)
		return exitUsage
	case errors.Is(err, flag.ErrHelp):
		fmt.Fprintln(e.err, adminUsage)
		return exitOK
	}
	fmt.Fprintln(e.err, "error:", describe(err))
	return 1
}

// describe renders service errors with the API's refusals in words.
func describe(err error) string {
	var sole users.SoleAdminError
	if errors.As(err, &sole) {
		ids := make([]string, len(sole.VaultIDs))
		for i, id := range sole.VaultIDs {
			ids[i] = id.String()
		}
		return fmt.Sprintf("the user owns %d vault(s) (%s): transfer them first, or pass --delete-owned-vaults to delete them too",
			len(ids), strings.Join(ids, ", "))
	}
	var ie *admin.InvalidError
	if errors.As(err, &ie) {
		return "invalid " + ie.Error()
	}
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return "not found"
	case errors.Is(err, domain.ErrConflict):
		return "conflict: " + err.Error()
	}
	return err.Error()
}

func (e *cliEnv) dispatch(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	cmds := map[string]map[string]func(context.Context, *admin.Service, []string) error{
		"token":   {"create": e.tokenCreate, "list": e.tokenList, "revoke": e.tokenRevoke},
		"user":    {"list": e.userList, "show": e.userShow, "create": e.userCreate, "password": e.userPassword, "disable": e.userState("disable"), "enable": e.userState("enable"), "unlock": e.userState("unlock"), "delete": e.userDelete},
		"session": {"list": e.sessionList, "revoke": e.sessionRevoke},
		"vault":   {"list": e.vaultList, "show": e.vaultShow, "delete": e.vaultDelete},
		"federation": {"list": e.federationList, "revoke": e.federationRevoke, "status": e.federationStatus,
			"pause": e.federationOp("pause"), "resume": e.federationOp("resume")},
		"mirror": {"list": e.mirrorList, "status": e.federationStatus, "resync": e.federationOp("resync"),
			"pause": e.federationOp("pause"), "resume": e.federationOp("resume"), "promote": e.mirrorPromote},
		"admin":   {"list": e.adminList, "grant": e.adminFlag(true), "revoke": e.adminFlag(false)},
		"publish": {"enable": e.publishEnable, "disable": e.publishDisable, "list": e.publishList},
	}
	var fn func(context.Context, *admin.Service, []string) error
	rest := args[1:]
	switch args[0] {
	case "status":
		fn = e.status
	case "audit":
		fn = e.audit
	default:
		group, ok := cmds[args[0]]
		if !ok || len(rest) == 0 {
			return errUsage
		}
		if fn, ok = group[rest[0]]; !ok {
			return errUsage
		}
		rest = rest[1:]
	}
	svc, closeFn, err := e.open(ctx)
	if err != nil {
		return err
	}
	defer closeFn()
	return fn(ctx, svc, rest)
}

// parse accepts flags before, between or after positionals and requires
// exactly want positionals.
func parse(fs *flag.FlagSet, args []string, want int) ([]string, error) {
	fs.SetOutput(io.Discard)
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return nil, err
			}
			return nil, fmt.Errorf("%w: %v", errUsage, err)
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
	if len(pos) != want {
		return nil, errUsage
	}
	return pos, nil
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func table(w io.Writer, header []string, rows [][]string) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(header, "\t"))
	for _, r := range rows {
		fmt.Fprintln(tw, strings.Join(r, "\t"))
	}
	return tw.Flush()
}

func stamp(t time.Time) string { return t.Local().Format("2006-01-02 15:04") }

func stampPtr(t *time.Time, none string) string {
	if t == nil {
		return none
	}
	return stamp(*t)
}

// liveNote tells the operator how a CLI change reaches a running server.
func (e *cliEnv) liveNote(what string) {
	fmt.Fprintln(e.err, "note: a running lumi-server sees this at once in the database; "+what)
}

// parseTTL accepts Go durations plus a day suffix ("30d").
func parseTTL(s string) (time.Duration, error) {
	if d, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(d)
		if err != nil {
			return 0, fmt.Errorf("invalid ttl %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid ttl %q", s)
	}
	return d, nil
}

// ---- tokens --------------------------------------------------------------------

// tokenCreate prints the token alone on stdout, so
// TOKEN=$(lumi-server token create panel) works; the rest goes to stderr.
// It is the only place an admin token is ever shown.
func (e *cliEnv) tokenCreate(ctx context.Context, svc *admin.Service, args []string) error {
	fs := flag.NewFlagSet("token create", flag.ContinueOnError)
	ttlRaw := fs.String("ttl", "30d", "")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	ttl, err := parseTTL(*ttlRaw)
	if err != nil {
		return &admin.InvalidError{Field: "ttl", Detail: err.Error()}
	}
	raw, t, err := svc.CreateToken(ctx, admin.CLI, pos[0], ttl)
	if err != nil {
		return err
	}
	fmt.Fprintf(e.err, "created admin token %s (%s), valid until %s; it is shown only once\n", t.ID, t.Name, stamp(t.ExpiresAt))
	_, err = fmt.Fprintln(e.out, raw)
	return err
}

func (e *cliEnv) tokenList(ctx context.Context, svc *admin.Service, args []string) error {
	fs := flag.NewFlagSet("token list", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	list, _, err := svc.ListTokens(ctx, nil, 0)
	if err != nil {
		return err
	}
	now := time.Now()
	if *asJSON {
		out := make([]admin.TokenJSON, 0, len(list))
		for _, t := range list {
			out = append(out, admin.ToTokenJSON(now, uuid.Nil)(t))
		}
		return printJSON(e.out, out)
	}
	rows := make([][]string, 0, len(list))
	for _, t := range list {
		kind, user := admin.KindToken, "-"
		if t.IsSession() {
			kind, user = admin.KindSession, t.Username
		}
		rows = append(rows, []string{t.ID.String(), kind, t.Name, user, t.State(now), stamp(t.CreatedAt), stampPtr(t.LastUsedAt, "never"), stamp(t.ExpiresAt)})
	}
	return table(e.out, []string{"ID", "KIND", "NAME", "USER", "STATE", "CREATED", "LAST USED", "EXPIRES"}, rows)
}

func (e *cliEnv) tokenRevoke(ctx context.Context, svc *admin.Service, args []string) error {
	pos, err := parse(flag.NewFlagSet("token revoke", flag.ContinueOnError), args, 1)
	if err != nil {
		return err
	}
	id, err := uuid.Parse(pos[0])
	if err != nil {
		return fmt.Errorf("token %q: %w", pos[0], domain.ErrNotFound)
	}
	if err := svc.RevokeToken(ctx, admin.CLI, id); err != nil {
		return err
	}
	_, err = fmt.Fprintf(e.out, "revoked admin token %s\n", id)
	return err
}

// ---- status -----------------------------------------------------------------------

func (e *cliEnv) status(ctx context.Context, svc *admin.Service, args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	st, err := svc.Status(ctx)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(e.out, map[string]any{
			"version": st.Version, "schema_version": st.SchemaVersion, "schema_dirty": st.SchemaDirty,
			"pending_migrations": st.PendingMigrations, "users": st.Users, "sessions": st.Sessions,
			"vaults": st.Vaults, "notes": st.Notes, "federations": st.Federations,
		})
	}
	fmt.Fprintf(e.out, "lumi-server %s\ndatabase: schema version %d (dirty: %v), %d pending migration(s)\n",
		st.Version, st.SchemaVersion, st.SchemaDirty, st.PendingMigrations)
	if st.PendingMigrations > 0 {
		fmt.Fprintln(e.out, "run `lumi-server migrate up` to apply them")
	}
	_, err = fmt.Fprintf(e.out, "users: %d\nsessions: %d\nvaults: %d\nnotes: %d\nfederations: %d active\n",
		st.Users, st.Sessions, st.Vaults, st.Notes, st.Federations)
	return err
}

// ---- server admins ----------------------------------------------------------------------

func (e *cliEnv) adminList(ctx context.Context, svc *admin.Service, args []string) error {
	fs := flag.NewFlagSet("admin list", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	list, _, err := svc.SearchUsers(ctx, admin.UserFilter{ServerAdmin: true}, "", 0)
	if err != nil {
		return err
	}
	now := time.Now()
	if *asJSON {
		out := make([]admin.UserJSON, 0, len(list))
		for _, u := range list {
			out = append(out, admin.ToUserJSON(now)(u))
		}
		return printJSON(e.out, out)
	}
	rows := make([][]string, 0, len(list))
	for _, u := range list {
		rows = append(rows, []string{u.ID.String(), u.Username, u.State(now), stamp(u.CreatedAt)})
	}
	return table(e.out, []string{"ID", "USERNAME", "STATE", "CREATED"}, rows)
}

// adminFlag grants or revokes server_admin. Revoking the last active
// server admin is refused, as in the API.
func (e *cliEnv) adminFlag(enabled bool) func(context.Context, *admin.Service, []string) error {
	return func(ctx context.Context, svc *admin.Service, args []string) error {
		pos, err := parse(flag.NewFlagSet("admin", flag.ContinueOnError), args, 1)
		if err != nil {
			return err
		}
		u, err := svc.ResolveUser(ctx, pos[0])
		if err != nil {
			return err
		}
		if err := svc.SetServerAdmin(ctx, admin.CLI, u.ID, enabled); err != nil {
			if errors.Is(err, admin.ErrLastServerAdmin) {
				return fmt.Errorf("%s is the last active server admin: grant another account first", u.Username)
			}
			return err
		}
		verb := "is now a server admin (panel password login)"
		if !enabled {
			verb = "is no longer a server admin; their admin sessions were ended"
		}
		_, err = fmt.Fprintf(e.out, "%s %s\n", u.Username, verb)
		return err
	}
}

// ---- users ----------------------------------------------------------------------------

func (e *cliEnv) userList(ctx context.Context, svc *admin.Service, args []string) error {
	fs := flag.NewFlagSet("user list", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	list, _, err := svc.ListUsers(ctx, "", 0)
	if err != nil {
		return err
	}
	now := time.Now()
	if *asJSON {
		out := make([]admin.UserJSON, 0, len(list))
		for _, u := range list {
			out = append(out, admin.ToUserJSON(now)(u))
		}
		return printJSON(e.out, out)
	}
	rows := make([][]string, 0, len(list))
	for _, u := range list {
		rows = append(rows, []string{u.ID.String(), u.Username, u.State(now), strconv.Itoa(u.Sessions),
			strconv.Itoa(u.OwnedVaults), strconv.Itoa(u.Vaults), stamp(u.CreatedAt)})
	}
	return table(e.out, []string{"ID", "USERNAME", "STATE", "SESSIONS", "OWNED", "VAULTS", "CREATED"}, rows)
}

func (e *cliEnv) userShow(ctx context.Context, svc *admin.Service, args []string) error {
	fs := flag.NewFlagSet("user show", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	u, err := svc.ResolveUser(ctx, pos[0])
	if err != nil {
		return err
	}
	out := admin.ToUserJSON(time.Now())(u)
	if out.OwnedVaultIDs, err = svc.Store.OwnedVaultIDs(ctx, u.ID); err != nil {
		return err
	}
	if out.OwnedVaultIDs == nil {
		out.OwnedVaultIDs = []uuid.UUID{}
	}
	if *asJSON {
		return printJSON(e.out, out)
	}
	fmt.Fprintf(e.out, "id: %s\nusername: %s\ndisplay name: %s\nstate: %s\nfailed logins: %d\nlocked until: %s\nsessions: %d\nowned vaults: %d %v\nvaults: %d\ncreated: %s\n",
		u.ID, u.Username, u.DisplayName, out.State, u.FailedLogins, stampPtr(u.LockedUntil, "-"),
		u.Sessions, u.OwnedVaults, out.OwnedVaultIDs, u.Vaults, stamp(u.CreatedAt))
	return nil
}

// readNewPassword reads one line from stdin with --password-stdin, or
// prompts twice without echo on a terminal.
func (e *cliEnv) readNewPassword(fromStdin bool, who string) (string, error) {
	if fromStdin {
		line, err := bufio.NewReader(e.in).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	if !e.terminal {
		return "", errors.New("stdin is not a terminal: pass --password-stdin and pipe the password")
	}
	pw, err := e.readPass("New password for " + who + ": ")
	if err != nil {
		return "", err
	}
	again, err := e.readPass("Repeat: ")
	if err != nil {
		return "", err
	}
	if pw != again {
		return "", errors.New("the passwords differ")
	}
	return pw, nil
}

func (e *cliEnv) userCreate(ctx context.Context, svc *admin.Service, args []string) error {
	fs := flag.NewFlagSet("user create", flag.ContinueOnError)
	display := fs.String("display-name", "", "")
	stdin := fs.Bool("password-stdin", false, "")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	pw, err := e.readNewPassword(*stdin, pos[0])
	if err != nil {
		return err
	}
	u, err := svc.CreateUser(ctx, admin.CLI, pos[0], pw, *display)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(e.out, "created user %s (%s)\n", u.Username, u.ID)
	return err
}

func (e *cliEnv) userPassword(ctx context.Context, svc *admin.Service, args []string) error {
	fs := flag.NewFlagSet("user password", flag.ContinueOnError)
	stdin := fs.Bool("password-stdin", false, "")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	u, err := svc.ResolveUser(ctx, pos[0])
	if err != nil {
		return err
	}
	pw, err := e.readNewPassword(*stdin, u.Username)
	if err != nil {
		return err
	}
	if err := svc.SetPassword(ctx, admin.CLI, u.ID, pw); err != nil {
		return err
	}
	fmt.Fprintf(e.out, "password of %s replaced; their sessions ended\n", u.Username)
	e.liveNote("open feed streams close within a minute; open note-sync WebSockets stay until they reconnect")
	return nil
}

// userState is disable, enable or unlock.
func (e *cliEnv) userState(op string) func(context.Context, *admin.Service, []string) error {
	ops := map[string]struct {
		fn   func(*admin.Service, context.Context, admin.Actor, uuid.UUID) error
		done string
	}{
		"disable": {(*admin.Service).Disable, "disabled"},
		"enable":  {(*admin.Service).Enable, "enabled"},
		"unlock":  {(*admin.Service).Unlock, "unlocked"},
	}
	return func(ctx context.Context, svc *admin.Service, args []string) error {
		pos, err := parse(flag.NewFlagSet("user "+op, flag.ContinueOnError), args, 1)
		if err != nil {
			return err
		}
		u, err := svc.ResolveUser(ctx, pos[0])
		if err != nil {
			return err
		}
		if err := ops[op].fn(svc, ctx, admin.CLI, u.ID); err != nil {
			return err
		}
		fmt.Fprintf(e.out, "%s user %s\n", ops[op].done, u.Username)
		if op == "disable" {
			e.liveNote("open feed streams close within a minute; open note-sync WebSockets stay until they reconnect")
		}
		return nil
	}
}

// confirm requires --yes, or the target's name typed on a terminal.
func (e *cliEnv) confirm(yes bool, what, name string) error {
	if yes {
		return nil
	}
	if !e.terminal {
		return fmt.Errorf("refusing to delete %s without --yes (stdin is not a terminal)", what)
	}
	fmt.Fprintf(e.err, "This permanently deletes %s. Type %q to confirm: ", what, name)
	line, _ := bufio.NewReader(e.in).ReadString('\n')
	if strings.TrimSpace(line) != name {
		return errors.New("not confirmed")
	}
	return nil
}

func (e *cliEnv) userDelete(ctx context.Context, svc *admin.Service, args []string) error {
	fs := flag.NewFlagSet("user delete", flag.ContinueOnError)
	force := fs.Bool("delete-owned-vaults", false, "")
	yes := fs.Bool("yes", false, "")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	u, err := svc.ResolveUser(ctx, pos[0])
	if err != nil {
		return err
	}
	// Refuse before asking for confirmation: same check DeleteUser makes.
	if owned, err := svc.Store.OwnedVaultIDs(ctx, u.ID); err != nil {
		return err
	} else if len(owned) > 0 && !*force {
		return users.SoleAdminError{VaultIDs: owned}
	}
	what := "user " + u.Username
	if *force && u.OwnedVaults > 0 {
		what += fmt.Sprintf(" and the %d vault(s) they own", u.OwnedVaults)
	}
	if err := e.confirm(*yes, what, u.Username); err != nil {
		return err
	}
	if err := svc.DeleteUser(ctx, admin.CLI, u.ID, *force); err != nil {
		return err
	}
	fmt.Fprintf(e.out, "deleted user %s (%s)\n", u.Username, u.ID)
	e.liveNote("open feed streams close within a minute; open note-sync WebSockets stay until they reconnect")
	return nil
}

// ---- sessions ------------------------------------------------------------------------------

func (e *cliEnv) sessionList(ctx context.Context, svc *admin.Service, args []string) error {
	fs := flag.NewFlagSet("session list", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	userRef := fs.String("user", "", "")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	var uid *uuid.UUID
	if *userRef != "" {
		u, err := svc.ResolveUser(ctx, *userRef)
		if err != nil {
			return err
		}
		uid = &u.ID
	}
	list, _, err := svc.ListSessions(ctx, uid, nil, 0)
	if err != nil {
		return err
	}
	if *asJSON {
		out := make([]admin.SessionJSON, 0, len(list))
		for _, s := range list {
			out = append(out, admin.ToSessionJSON(s))
		}
		return printJSON(e.out, out)
	}
	rows := make([][]string, 0, len(list))
	for _, s := range list {
		rows = append(rows, []string{s.ID, s.Username, stamp(s.CreatedAt), stamp(s.LastUsedAt), stamp(s.ExpiresAt)})
	}
	return table(e.out, []string{"ID", "USER", "CREATED", "LAST USED", "EXPIRES"}, rows)
}

func (e *cliEnv) sessionRevoke(ctx context.Context, svc *admin.Service, args []string) error {
	pos, err := parse(flag.NewFlagSet("session revoke", flag.ContinueOnError), args, 1)
	if err != nil {
		return err
	}
	if err := svc.RevokeSession(ctx, admin.CLI, pos[0]); err != nil {
		return err
	}
	fmt.Fprintln(e.out, "revoked session", pos[0])
	e.liveNote("its open feed streams close within a minute; open note-sync WebSockets stay until they reconnect")
	return nil
}

// ---- vaults ---------------------------------------------------------------------------------

func (e *cliEnv) vaultList(ctx context.Context, svc *admin.Service, args []string) error {
	fs := flag.NewFlagSet("vault list", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	userRef := fs.String("user", "", "")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	var uid *uuid.UUID
	if *userRef != "" {
		u, err := svc.ResolveUser(ctx, *userRef)
		if err != nil {
			return err
		}
		uid = &u.ID
	}
	list, _, err := svc.ListVaults(ctx, uid, "", 0)
	if err != nil {
		return err
	}
	if *asJSON {
		out := make([]admin.VaultJSON, 0, len(list))
		for _, v := range list {
			out = append(out, admin.ToVaultJSON(v))
		}
		return printJSON(e.out, out)
	}
	rows := make([][]string, 0, len(list))
	for _, v := range list {
		fed := "-"
		if v.FederationRole != nil {
			fed = fmt.Sprintf("%s (%d)", *v.FederationRole, v.ActiveFederations)
		}
		rows = append(rows, []string{v.ID.String(), v.Slug, v.OwnerUsername, strconv.Itoa(v.Members),
			strconv.Itoa(v.Notes), strconv.FormatInt(v.CRDTBytes, 10), fed, stamp(v.CreatedAt)})
	}
	return table(e.out, []string{"ID", "SLUG", "OWNER", "MEMBERS", "NOTES", "CRDT BYTES", "FEDERATION", "CREATED"}, rows)
}

func (e *cliEnv) vaultShow(ctx context.Context, svc *admin.Service, args []string) error {
	fs := flag.NewFlagSet("vault show", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	v, err := svc.ResolveVault(ctx, pos[0])
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(e.out, admin.ToVaultJSON(v))
	}
	fed := "none"
	if v.FederationRole != nil {
		fed = fmt.Sprintf("%s, %d active link(s)", *v.FederationRole, v.ActiveFederations)
	}
	_, err = fmt.Fprintf(e.out, "id: %s\nslug: %s\nname: %s\nowner: %s (%s)\nmembers: %d (+%d federated)\nnotes: %d\ncrdt bytes: %d\nfederation: %s\ncreated: %s\n",
		v.ID, v.Slug, v.Name, v.OwnerUsername, v.OwnerID, v.Members, v.FederatedMembers, v.Notes, v.CRDTBytes, fed, stamp(v.CreatedAt))
	return err
}

func (e *cliEnv) vaultDelete(ctx context.Context, svc *admin.Service, args []string) error {
	fs := flag.NewFlagSet("vault delete", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	v, err := svc.ResolveVault(ctx, pos[0])
	if err != nil {
		return err
	}
	if err := e.confirm(*yes, "vault "+v.Slug+" and all its notes", v.Slug); err != nil {
		return err
	}
	if err := svc.DeleteVault(ctx, admin.CLI, v.ID); err != nil {
		return err
	}
	fmt.Fprintf(e.out, "deleted vault %s (%s)\n", v.Slug, v.ID)
	e.liveNote("members' feeds drop the vault at their next re-check (within a minute)")
	return nil
}

// ---- federations -----------------------------------------------------------------------------

func (e *cliEnv) federationList(ctx context.Context, svc *admin.Service, args []string) error {
	return e.listLinks(ctx, svc, "federation list", "", args)
}

func (e *cliEnv) mirrorList(ctx context.Context, svc *admin.Service, args []string) error {
	return e.listLinks(ctx, svc, "mirror list", "mirror", args)
}

func (e *cliEnv) listLinks(ctx context.Context, svc *admin.Service, name, mode string, args []string) error {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	vaultRef := fs.String("vault", "", "")
	modeFlag := fs.String("mode", mode, "")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	var vid *uuid.UUID
	if *vaultRef != "" {
		v, err := svc.ResolveVault(ctx, *vaultRef)
		if err != nil {
			return err
		}
		vid = &v.ID
	}
	list, _, err := svc.ListFederations(ctx, admin.FederationFilter{VaultID: vid, Mode: *modeFlag}, nil, 0)
	if err != nil {
		return err
	}
	if *asJSON {
		out := make([]admin.FederationJSON, 0, len(list))
		for _, f := range list {
			out = append(out, admin.ToFederationJSON(f))
		}
		return printJSON(e.out, out)
	}
	rows := make([][]string, 0, len(list))
	for _, f := range list {
		status := f.Status
		if f.PausedAt != nil {
			status += " (paused)"
		}
		if f.PromotedAt != nil {
			status += " (promoted)"
		}
		rows = append(rows, []string{f.ID.String(), f.VaultSlug, f.Role, orDash(f.Mode), f.PeerURL, status, linkLag(f), stamp(f.CreatedAt)})
	}
	return table(e.out, []string{"ID", "VAULT", "ROLE", "MODE", "PEER", "STATUS", "LAG", "CREATED"}, rows)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// linkLag is the LAG column: home side of a mirror = seqs behind and
// pending deletes; mirror side = applied home seq.
func linkLag(f admin.Federation) string {
	switch {
	case f.Mode == "mirror" && f.Role == "home":
		return fmt.Sprintf("%d (%d deletes)", f.LagSeq(), f.PendingDeletes)
	case f.Mode == "mirror":
		return fmt.Sprintf("@%d", f.HomeSeq)
	}
	return "-"
}

func (e *cliEnv) federationStatus(ctx context.Context, svc *admin.Service, args []string) error {
	fs := flag.NewFlagSet("federation status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	id, err := uuid.Parse(pos[0])
	if err != nil {
		return fmt.Errorf("federation %q: %w", pos[0], domain.ErrNotFound)
	}
	f, err := svc.GetFederation(ctx, id)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(e.out, admin.ToFederationJSON(f))
	}
	j := admin.ToFederationJSON(f)
	opt := func(p *string) string {
		if p == nil {
			return "-"
		}
		return *p
	}
	w := tabwriter.NewWriter(e.out, 0, 2, 2, ' ', 0)
	fmt.Fprintf(w, "id\t%s\n", j.ID)
	fmt.Fprintf(w, "vault\t%s (%s)\n", j.Vault.Slug, j.Vault.ID)
	fmt.Fprintf(w, "role / mode\t%s / %s\n", j.Role, j.Mode)
	fmt.Fprintf(w, "peer\t%s\n", j.PeerURL)
	fmt.Fprintf(w, "status\t%s\n", j.Status)
	fmt.Fprintf(w, "sever policy\t%s\n", j.SeverPolicy)
	fmt.Fprintf(w, "paused at\t%s\n", opt(j.PausedAt))
	fmt.Fprintf(w, "last contact\t%s\n", opt(j.LastContactAt))
	if j.Mode == "mirror" && j.Role == "home" {
		fmt.Fprintf(w, "head / acked\t%d / %d (lag %d)\n", j.HeadSeq, j.MirrorAckedSeq, j.LagSeq)
		fmt.Fprintf(w, "pending deletes\t%d (oldest %s)\n", j.PendingDeletes, opt(j.OldestPendingDeleteAt))
		fmt.Fprintf(w, "violations 24h\t%d\n", j.Violations24h)
	}
	if j.Mode == "mirror" && j.Role == "follower" {
		fmt.Fprintf(w, "home seq applied\t%d\n", j.HomeSeq)
		fmt.Fprintf(w, "promoted at\t%s\n", opt(j.PromotedAt))
		if j.Backfill != nil {
			fmt.Fprintf(w, "backfill\t%d/%d (active %v)\n", j.Backfill.Synced, j.Backfill.Total, j.Backfill.Active)
		}
	}
	return w.Flush()
}

// federationOp runs pause/resume/resync on a link by id.
func (e *cliEnv) federationOp(op string) func(context.Context, *admin.Service, []string) error {
	return func(ctx context.Context, svc *admin.Service, args []string) error {
		pos, err := parse(flag.NewFlagSet("federation "+op, flag.ContinueOnError), args, 1)
		if err != nil {
			return err
		}
		id, err := uuid.Parse(pos[0])
		if err != nil {
			return fmt.Errorf("federation %q: %w", pos[0], domain.ErrNotFound)
		}
		switch op {
		case "pause":
			_, err = svc.PauseFederation(ctx, admin.CLI, id)
		case "resume":
			_, err = svc.ResumeFederation(ctx, admin.CLI, id)
		case "resync":
			_, err = svc.ResyncMirror(ctx, admin.CLI, id)
		}
		if err != nil {
			return err
		}
		done := map[string]string{"pause": "paused", "resume": "resumed", "resync": "resync requested for"}[op]
		fmt.Fprintf(e.out, "%s federation %s (a running server applies it within 15 s)\n", done, id)
		return nil
	}
}

// mirrorPromote is CLI-only on purpose: an admin token alone must not be
// able to fork a book (docs/SPEC-ESPELHO-SELADO.md §A12).
func (e *cliEnv) mirrorPromote(ctx context.Context, svc *admin.Service, args []string) error {
	fs := flag.NewFlagSet("mirror promote", flag.ContinueOnError)
	confirm := fs.Bool("confirm", false, "")
	pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	if !*confirm {
		return fmt.Errorf("%w: promotion turns this mirror into an independent, writable home and cannot be undone: pass --confirm", domain.ErrValidation)
	}
	v, res, err := svc.PromoteMirror(ctx, admin.CLI, pos[0])
	if err != nil {
		return err
	}
	fmt.Fprintf(e.out, "promoted mirror %s (%s); link to %s severed\n", v.Slug, v.ID, res.PeerURL)
	if len(res.RolesCreated)+len(res.RolesUpdated) > 0 {
		fmt.Fprintf(e.out, "roles created: %s; updated: %s\n", strings.Join(res.RolesCreated, ", "), strings.Join(res.RolesUpdated, ", "))
	}
	fmt.Fprintf(e.out, "members carried over: %s\n", joinOrNone(res.Members))
	if len(res.Missing) > 0 {
		fmt.Fprintf(e.out, "not carried over (no such user here): %s\n", strings.Join(res.Missing, ", "))
	}
	if len(res.Dropped) > 0 {
		fmt.Fprintf(e.out, "not carried over (other servers): %s\n", strings.Join(res.Dropped, ", "))
	}
	fmt.Fprintln(e.out, "restart lumi-server so the running process drops the old link and lifts the read-only mode at once")
	return nil
}

func joinOrNone(list []string) string {
	if len(list) == 0 {
		return "none"
	}
	return strings.Join(list, ", ")
}

func (e *cliEnv) federationRevoke(ctx context.Context, svc *admin.Service, args []string) error {
	pos, err := parse(flag.NewFlagSet("federation revoke", flag.ContinueOnError), args, 1)
	if err != nil {
		return err
	}
	id, err := uuid.Parse(pos[0])
	if err != nil {
		return fmt.Errorf("federation %q: %w", pos[0], domain.ErrNotFound)
	}
	if err := svc.RevokeFederation(ctx, admin.CLI, id); err != nil {
		return err
	}
	fmt.Fprintln(e.out, "revoked federation", id)
	e.liveNote("a relay link already open on it stays up until it reconnects or the server restarts; while the server runs, prefer DELETE /admin/v1/federations/{id}")
	return nil
}

// ---- audit ---------------------------------------------------------------------------------------

func (e *cliEnv) audit(ctx context.Context, svc *admin.Service, args []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "")
	limit := fs.Int("limit", 50, "")
	before := fs.Int64("before", 0, "")
	scope := fs.String("scope", "all", "")
	userRef := fs.String("user", "", "")
	vaultRef := fs.String("vault", "", "")
	if _, err := parse(fs, args, 0); err != nil {
		return err
	}
	if *limit < 1 || *limit > 1000 {
		return &admin.InvalidError{Field: "limit", Detail: "must be from 1 to 1000"}
	}
	q := admin.AuditQuery{Before: *before, Limit: *limit}
	switch *scope {
	case "all":
	case "admin":
		q.AdminOn = true
	default:
		return &admin.InvalidError{Field: "scope", Detail: "must be all or admin"}
	}
	if *userRef != "" {
		u, err := svc.ResolveUser(ctx, *userRef)
		if err != nil {
			return err
		}
		q.UserID = &u.ID
	}
	if *vaultRef != "" {
		v, err := svc.ResolveVault(ctx, *vaultRef)
		if err != nil {
			return err
		}
		q.VaultID = &v.ID
	}
	list, more, err := svc.ListAudit(ctx, q)
	if err != nil {
		return err
	}
	if *asJSON {
		out := make([]admin.AuditJSON, 0, len(list))
		for _, x := range list {
			out = append(out, admin.ToAuditJSON(x))
		}
		return printJSON(e.out, map[string]any{"entries": out, "more": more})
	}
	rows := make([][]string, 0, len(list))
	for _, x := range list {
		ip := "-"
		if x.IP != nil {
			ip = *x.IP
		}
		rows = append(rows, []string{strconv.FormatInt(x.ID, 10), stamp(x.CreatedAt), x.Action, ip, string(x.Payload)})
	}
	if err := table(e.out, []string{"ID", "AT", "ACTION", "IP", "PAYLOAD"}, rows); err != nil {
		return err
	}
	if more && len(list) > 0 {
		fmt.Fprintf(e.err, "more: --before %d\n", list[len(list)-1].ID)
	}
	return nil
}
