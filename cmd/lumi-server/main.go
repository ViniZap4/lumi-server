// Command lumi-server is the v2 multi-tenant collaborative note server.
//
// Subcommands:
//
//	lumi-server                    start the HTTP server
//	lumi-server migrate up         run all pending migrations
//	lumi-server migrate down N     roll back N migrations
//	lumi-server migrate status     print current migration version
//	lumi-server version            print version
package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
	"github.com/rs/zerolog"

	"github.com/ViniZap4/lumi-server/internal/audit"
	"github.com/ViniZap4/lumi-server/internal/auth"
	"github.com/ViniZap4/lumi-server/internal/crdt"
	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/federation"
	"github.com/ViniZap4/lumi-server/internal/fswatch"
	"github.com/ViniZap4/lumi-server/internal/invites"
	"github.com/ViniZap4/lumi-server/internal/members"
	"github.com/ViniZap4/lumi-server/internal/notes"
	"github.com/ViniZap4/lumi-server/internal/roles"
	"github.com/ViniZap4/lumi-server/internal/storage/fs"
	"github.com/ViniZap4/lumi-server/internal/storage/pg"
	"github.com/ViniZap4/lumi-server/internal/users"
	"github.com/ViniZap4/lumi-server/internal/vaults"
	"github.com/ViniZap4/lumi-server/internal/wsync"

	"github.com/google/uuid"
)

// authUserRepoAdapter bridges pg.UserStore to auth.UserRepo. The two
// CreateUser signatures take structurally identical inputs but live in
// different packages; one cheap adapter avoids polluting either package
// with a cross-import.
type authUserRepoAdapter struct{ *pg.UserStore }

func (a authUserRepoAdapter) CreateUser(ctx context.Context, in auth.CreateUserInput) (domain.User, error) {
	return a.UserStore.CreateUser(ctx, pg.CreateUserInput(in))
}

// crdtRepoAdapter bridges pg.NoteYjsStore to crdt.SnapshotRepo. The pg
// store returns its own DTO shapes; the crdt registry takes a smaller
// row type. Conversion is trivial; this adapter keeps the storage and
// crdt packages from cross-importing each other's types.
type crdtRepoAdapter struct{ *pg.NoteYjsStore }

func (a crdtRepoAdapter) GetSnapshot(ctx context.Context, vaultID uuid.UUID, noteID string) (crdt.SnapshotRow, error) {
	row, err := a.NoteYjsStore.GetSnapshot(ctx, vaultID, noteID)
	if err != nil {
		return crdt.SnapshotRow{}, err
	}
	return crdt.SnapshotRow{State: row.State}, nil
}

func (a crdtRepoAdapter) ListUpdatesSince(ctx context.Context, vaultID uuid.UUID, noteID string, sinceID int64, limit int) ([]crdt.UpdateRow, error) {
	rows, err := a.NoteYjsStore.ListUpdatesSince(ctx, vaultID, noteID, sinceID, limit)
	if err != nil {
		return nil, err
	}
	out := make([]crdt.UpdateRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, crdt.UpdateRow{ID: r.ID, Update: r.Update, OriginKind: r.OriginKind})
	}
	return out, nil
}

// memberRepoAdapter bridges pg.MemberStore to members.Repo. Same reason.
type memberRepoAdapter struct{ *pg.MemberStore }

func (a memberRepoAdapter) ListForVault(ctx context.Context, vaultID uuid.UUID) ([]members.MemberJoined, error) {
	pgRows, err := a.MemberStore.ListForVault(ctx, vaultID)
	if err != nil {
		return nil, err
	}
	out := make([]members.MemberJoined, 0, len(pgRows))
	for _, r := range pgRows {
		out = append(out, members.MemberJoined(r))
	}
	return out, nil
}

// Version is overridden at link time via -ldflags="-X main.Version=...".
var Version = "0.0.0-phase1"

const (
	exitOK         = 0
	exitUsage      = 64
	exitConfig     = 78
	exitTLSGate    = 80
	exitMigrate    = 81
	exitDB         = 82
	exitListenFail = 83
)

func main() {
	os.Exit(realMain(os.Args[1:]))
}

func realMain(args []string) int {
	if len(args) > 0 {
		switch args[0] {
		case "version", "-v", "--version":
			fmt.Fprintf(os.Stdout, "lumi-server %s\n", Version)
			return exitOK
		case "migrate":
			return migrateCmd(args[1:])
		case "help", "-h", "--help":
			printUsage()
			return exitOK
		default:
			fmt.Fprintf(os.Stderr, "unknown command %q\n", args[0])
			printUsage()
			return exitUsage
		}
	}
	return runServer()
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `lumi-server — multi-tenant collaborative note server

Usage:
  lumi-server                    start the HTTP server
  lumi-server migrate up         run all pending migrations
  lumi-server migrate down N     roll back N migrations
  lumi-server migrate status     print current migration version
  lumi-server version            print version

Configuration is via environment variables. See .env.example.`)
}

// ---------------------------------------------------------------- config ----

type config struct {
	databaseURL        string
	root               string
	port               int
	bindAddr           string
	requireTLS         bool
	allowedOrigins     []string
	registration       string
	auditRetentionDays int
	adminUsername      string
	adminPassword      string
	tosVersion         string
	privacyVersion     string
	publicBaseURL      string
	logFormat          string
	logLevel           string
	autoMigrate        bool
}

func loadConfig() (config, error) {
	c := config{
		databaseURL:    os.Getenv("LUMI_DATABASE_URL"),
		root:           os.Getenv("LUMI_ROOT"),
		bindAddr:       envDefault("LUMI_BIND_ADDR", "0.0.0.0"),
		registration:   envDefault("LUMI_REGISTRATION", "invite-only"),
		adminUsername:  os.Getenv("LUMI_ADMIN_USERNAME"),
		adminPassword:  os.Getenv("LUMI_ADMIN_PASSWORD"),
		tosVersion:     os.Getenv("LUMI_TOS_VERSION"),
		privacyVersion: os.Getenv("LUMI_PRIVACY_VERSION"),
		publicBaseURL:  os.Getenv("LUMI_PUBLIC_BASE_URL"),
		logFormat:      envDefault("LUMI_LOG_FORMAT", "json"),
		logLevel:       envDefault("LUMI_LOG_LEVEL", "info"),
	}
	port, err := envInt("LUMI_PORT", 8080)
	if err != nil {
		return config{}, err
	}
	c.port = port
	retention, err := envInt("LUMI_AUDIT_RETENTION_DAYS", 90)
	if err != nil {
		return config{}, err
	}
	c.auditRetentionDays = retention
	c.requireTLS = envBool("LUMI_REQUIRE_TLS", true)
	c.autoMigrate = envBool("LUMI_AUTO_MIGRATE", false)
	if origins := os.Getenv("LUMI_ALLOWED_ORIGINS"); origins != "" {
		for _, o := range strings.Split(origins, ",") {
			if o = strings.TrimSpace(o); o != "" {
				c.allowedOrigins = append(c.allowedOrigins, o)
			}
		}
	}
	if err := c.validate(); err != nil {
		return config{}, err
	}
	return c, nil
}

func (c config) validate() error {
	var problems []string
	if c.databaseURL == "" {
		problems = append(problems, "LUMI_DATABASE_URL is required")
	}
	if c.root == "" {
		problems = append(problems, "LUMI_ROOT is required")
	}
	if c.port < 1 || c.port > 65535 {
		problems = append(problems, fmt.Sprintf("LUMI_PORT %d out of range", c.port))
	}
	if c.auditRetentionDays < 1 {
		problems = append(problems, "LUMI_AUDIT_RETENTION_DAYS must be >= 1")
	}
	if c.registration != "open" && c.registration != "invite-only" {
		problems = append(problems, fmt.Sprintf("LUMI_REGISTRATION must be 'open' or 'invite-only', got %q", c.registration))
	}
	if (c.adminUsername == "") != (c.adminPassword == "") {
		problems = append(problems, "LUMI_ADMIN_USERNAME and LUMI_ADMIN_PASSWORD must be set together")
	}
	if c.publicBaseURL != "" {
		if _, err := url.ParseRequestURI(c.publicBaseURL); err != nil {
			problems = append(problems, fmt.Sprintf("LUMI_PUBLIC_BASE_URL invalid: %v", err))
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", domain.ErrValidation, strings.Join(problems, "; "))
	}
	return nil
}

func (c config) isLoopback() bool {
	return c.bindAddr == "127.0.0.1" || c.bindAddr == "::1" || c.bindAddr == "localhost"
}

func envDefault(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) (int, error) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%w: %s must be integer", domain.ErrValidation, key)
	}
	return n, nil
}

func envBool(key string, def bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "t", "true", "yes", "on":
		return true
	case "0", "f", "false", "no", "off":
		return false
	}
	return def
}

// ---------------------------------------------------------------- logger ----

func newLogger(cfg config) zerolog.Logger {
	zerolog.TimeFieldFormat = time.RFC3339Nano
	var w = os.Stdout
	level, err := zerolog.ParseLevel(cfg.logLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}
	if cfg.logFormat == "console" {
		return zerolog.New(zerolog.ConsoleWriter{Out: w, TimeFormat: time.RFC3339}).
			Level(level).With().Timestamp().Str("service", "lumi-server").Logger()
	}
	return zerolog.New(w).Level(level).With().Timestamp().Str("service", "lumi-server").Logger()
}

// ---------------------------------------------------------------- server ----

func runServer() int {
	_ = godotenv.Load()

	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		return exitConfig
	}
	zlog := newLogger(cfg)
	zlog.Info().
		Str("version", Version).
		Str("registration", cfg.registration).
		Bool("require_tls", cfg.requireTLS).
		Int("audit_retention_days", cfg.auditRetentionDays).
		Msg("lumi-server starting")

	if cfg.requireTLS && !cfg.isLoopback() {
		zlog.Error().
			Str("bind", cfg.bindAddr).
			Msg("LUMI_REQUIRE_TLS is true but bind is non-loopback; expecting upstream TLS termination. Set LUMI_REQUIRE_TLS=false to override.")
		return exitTLSGate
	}

	rootCtx, rootCancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer rootCancel()

	pool, err := pg.New(rootCtx, cfg.databaseURL)
	if err != nil {
		zlog.Error().Err(err).Msg("postgres connect")
		return exitDB
	}
	defer pool.Close()

	if cfg.autoMigrate {
		zlog.Info().Msg("LUMI_AUTO_MIGRATE=true: applying migrations")
		if err := pg.Migrate(rootCtx, cfg.databaseURL, migrationsDir()); err != nil {
			zlog.Error().Err(err).Msg("auto-migrate")
			return exitMigrate
		}
	}

	fsMgr, err := fs.NewManager(cfg.root)
	if err != nil {
		zlog.Error().Err(err).Msg("fs manager")
		return exitConfig
	}
	if err := fsMgr.EnsureRootDir(); err != nil {
		zlog.Error().Err(err).Msg("fs root dir")
		return exitConfig
	}

	app, shutdown, err := buildApp(rootCtx, cfg, zlog, pool, fsMgr)
	if err != nil {
		zlog.Error().Err(err).Msg("build app")
		return exitDB
	}

	listenErrCh := make(chan error, 1)
	go func() {
		addr := fmt.Sprintf("%s:%d", cfg.bindAddr, cfg.port)
		zlog.Info().Str("addr", addr).Msg("http server listening")
		listenErrCh <- app.Listen(addr)
	}()

	select {
	case <-rootCtx.Done():
		zlog.Info().Msg("signal received; shutting down")
	case err := <-listenErrCh:
		if err != nil {
			zlog.Error().Err(err).Msg("listener exited unexpectedly")
			_ = shutdown(context.Background())
			return exitListenFail
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := app.ShutdownWithContext(shutdownCtx); err != nil {
		zlog.Warn().Err(err).Msg("fiber shutdown error")
	}
	if err := shutdown(shutdownCtx); err != nil {
		zlog.Warn().Err(err).Msg("dependency shutdown error")
	}

	zlog.Info().Msg("lumi-server stopped")
	return exitOK
}

// shutdownFn closes whatever buildApp constructed.
type shutdownFn func(context.Context) error

func buildApp(ctx context.Context, cfg config, zlog zerolog.Logger, pool *pgxpool.Pool, fsMgr *fs.Manager) (*fiber.App, shutdownFn, error) {
	// Stores.
	userStore := pg.NewUserStore(pool)
	sessionStore := pg.NewSessionStore(pool)
	consentStore := pg.NewConsentStore(pool)
	auditStore := pg.NewAuditStore(pool)
	vaultStore := pg.NewVaultStore(pool)
	roleStore := pg.NewRoleStore(pool)
	memberStore := pg.NewMemberStore(pool)
	inviteStore := pg.NewInviteStore(pool)
	noteStore := pg.NewNoteStore(pool)
	noteYjsStore := pg.NewNoteYjsStore(pool)
	crdtRegistry := crdt.NewRegistry(crdtRepoAdapter{noteYjsStore})

	// Auth service.
	authCfg := auth.Config{
		BcryptCost:         12,
		SessionTTL:         30 * 24 * time.Hour,
		RegistrationPolicy: auth.RegistrationPolicy(cfg.registration),
		RequireConsent:     cfg.tosVersion != "" && cfg.privacyVersion != "",
		TosVersion:         cfg.tosVersion,
		PrivacyVersion:     cfg.privacyVersion,
		Logger:             zlog,
	}
	authSvc, err := auth.NewService(authUserRepoAdapter{userStore}, sessionStore, consentStore, auditStore, authCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("auth service: %w", err)
	}

	// Bootstrap admin if env supplies credentials and DB is empty.
	if err := auth.Bootstrap(ctx, authSvc, userStore, auth.BootstrapConfig{
		Username: cfg.adminUsername,
		Password: cfg.adminPassword,
	}); err != nil {
		return nil, nil, fmt.Errorf("auth bootstrap: %w", err)
	}

	// Domain services.
	rolesSvc := roles.NewService(roleStore, auditStore)
	membersSvc := members.NewService(memberRepoAdapter{memberStore}, auditStore)
	membersSvc.SetVaultLookup(vaultStore)
	vaultsSvc := vaults.NewService(vaultStore, roleStore, memberStore, fsMgr, auditStore, membersSvc)
	usersSvc := users.NewService(userStore, consentStore, auditStore, auditStore, vaultStore)
	usersSvc.SetVaultDirRemover(fsMgr)
	// FS watcher. Handler is set below once the WS hub exists; the
	// silencer side (SkipNext) is what notes.Service needs at this
	// point, and that surface is available immediately.
	fsWatcher, err := fswatch.New(fsMgr.Root, fsMgr, nil, zlog)
	if err != nil {
		return nil, nil, fmt.Errorf("fswatch: %w", err)
	}

	notesSvc := notes.NewService(noteStore, vaultStore, fsMgr, auditStore, membersSvc, crdtRegistry, fsWatcher)
	wsHub := wsync.NewHub(crdtRegistry, wsync.WithFSMirror(notesSvc.WriteBodyFromCRDT))

	fsWatcher.SetHandler(buildFSHandler(zlog, vaultStore, noteStore, fsMgr, crdtRegistry, wsHub))
	vaultsSvc.SetWatcher(fsWatcher)
	vaultsSvc.SetOwnershipDeps(memberStore, userStore, notesSvc)
	if err := fsWatcher.WatchExistingVaults(); err != nil {
		zlog.Warn().Err(err).Msg("fswatch: WatchExistingVaults")
	}
	go fsWatcher.Run(ctx)
	federationSvc, err := federation.NewService(ctx, federation.Deps{
		Keys:        pg.NewServerKeyStore(pool),
		Federations: pg.NewFederationStore(pool),
		Invites:     pg.NewFederationInviteStore(pool),
		Vaults:      vaultStore,
		Creator:     vaultsSvc,
		Audit:       auditStore,
		BaseURL:     cfg.publicBaseURL,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("federation service: %w", err)
	}
	// F2 content relay: live sessions registry + follower dial loops. The
	// registry persist hook is the fan-out point for every write path;
	// note creations get their own nudge (InitFromText bypasses the hook).
	relayLinks := federation.NewLinks(ctx, federation.RelayDeps{
		Registry: crdtRegistry,
		Rooms:    wsHub,
		Notes:    noteStore,
		Mirror:   notesSvc.WriteBodyFromCRDT,
		Log:      zlog,
	})
	crdtRegistry.SetOnPersist(relayLinks.OnPersist)
	notesSvc.SetFederationNotifier(relayLinks)
	relayManager := federation.NewManager(federationSvc, relayLinks, nil, zlog)
	federationSvc.SetLinkController(relayManager)
	if err := relayManager.Start(ctx); err != nil {
		zlog.Warn().Err(err).Msg("federation: relay manager start")
	}
	invitesSvc := invites.NewService(invites.Deps{
		Repo:          inviteStore,
		Users:         userStore,
		Members:       memberStore,
		Vaults:        vaultStore,
		Roles:         roleStore,
		Consents:      consentStore,
		Sessions:      sessionStore,
		Hasher:        authSvc,
		Tokens:        authSvc,
		Audit:         auditStore,
		PublicBaseURL: cfg.publicBaseURL,
	})

	// Fiber app. BodyLimit is set to 4 MiB to accommodate note bodies;
	// auth/admin payloads are < 1 KiB so the larger cap costs nothing.
	app := fiber.New(fiber.Config{
		AppName:               "lumi-server " + Version,
		BodyLimit:             4 << 20,
		ReadTimeout:           30 * time.Second,
		WriteTimeout:          60 * time.Second,
		IdleTimeout:           120 * time.Second,
		DisableStartupMessage: true,
		Prefork:               false,
	})

	app.Use(requestid.New())
	app.Use(recover.New())
	app.Use(securityHeaders())
	app.Use(corsMiddleware(cfg.allowedOrigins))
	app.Use(accessLog(zlog))

	// Health.
	app.Get("/healthz", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})
	app.Get("/readyz", func(c *fiber.Ctx) error {
		pingCtx, cancel := context.WithTimeout(c.UserContext(), 2*time.Second)
		defer cancel()
		if err := pool.Ping(pingCtx); err != nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"status": "unavailable"})
		}
		return c.JSON(fiber.Map{"status": "ok"})
	})

	// Auth handlers register their own routes (public + Required-protected).
	auth.NewHandlers(authSvc).Register(app)

	// Authenticated group for everything else.
	authed := app.Group("/api", auth.Required(authSvc))

	users.NewHandlers(usersSvc, authSvc).Register(authed)
	vaults.NewHandlers(vaultsSvc).Register(authed)
	roles.NewHandlers(rolesSvc, membersSvc).Register(authed)
	members.NewHandlers(membersSvc, membersSvc).Register(authed)
	audit.NewHandlers(auditStore, membersSvc).Register(authed)
	notes.NewHandlers(notesSvc).Register(authed)
	wsync.NewHandler(wsHub, membersSvc, cfg.allowedOrigins).Register(authed)

	// Invites: split between vault-scoped (authed) and public.
	invites.NewHandlers(invitesSvc).Register(app, authed, membersSvc)
	federation.NewHandlers(federationSvc, membersSvc).Register(app, authed)
	federation.NewRelayHandlers(federationSvc, relayLinks, zlog).Register(app)

	shutdown := func(ctx context.Context) error {
		_ = ctx
		_ = fsWatcher.Close()
		wsHub.Close()
		return nil
	}
	return app, shutdown, nil
}

// buildFSHandler stitches an fswatch.Handler that routes external markdown
// edits into the CRDT layer. Pipeline:
//
//  1. Look up the vault by on-disk slug (skip if unknown — could be a
//     stale dir left behind by a deleted vault).
//  2. Look up the note row by path (skip if no row — Phase 2.4 does NOT
//     auto-create on drop-in files; that's a 2.4.b call).
//  3. Read frontmatter + body from disk.
//  4. If a live WS Room exists, drive the change through it so
//     subscribers see the broadcast; otherwise apply + persist via the
//     CRDT registry directly.
//  5. The note's pg row gets updated_at bumped so list/search reflects
//     the external edit.
//
// Errors are logged but never propagated — the watcher is a best-effort
// background process; one bad file should not stall others.
func buildFSHandler(
	zlog zerolog.Logger,
	vaultStore *pg.VaultStore,
	noteStore *pg.NoteStore,
	fsMgr *fs.Manager,
	crdtReg *crdt.Registry,
	hub *wsync.Hub,
) fswatch.Handler {
	const originKind = "fs-watcher"
	log := zlog.With().Str("component", "fswatch.handler").Logger()
	return fswatch.HandlerFunc(func(ctx context.Context, ev fswatch.Event) {
		v, err := vaultStore.GetBySlug(ctx, ev.VaultSlug)
		if err != nil {
			log.Debug().Err(err).Str("slug", ev.VaultSlug).Msg("vault lookup failed")
			return
		}
		n, err := noteStore.GetByPath(ctx, v.ID, ev.RelativePath)
		if err != nil {
			log.Debug().Err(err).Str("path", ev.RelativePath).Msg("note lookup failed (no auto-create in 2.4)")
			return
		}
		_, body, err := fsMgr.ReadNote(v.Slug, n.Path)
		if err != nil {
			log.Warn().Err(err).Str("path", n.Path).Msg("read note failed")
			return
		}

		// If subscribers are connected, drive the diff through the
		// live Room so they see the update. Otherwise apply + persist
		// without touching the WS layer.
		newText := string(body)
		if room := hub.RoomIfActive(v.ID, n.ID); room != nil {
			doc := room.Doc()
			update, err := doc.ApplyTextDiff(newText, originKind)
			if err != nil {
				log.Warn().Err(err).Msg("live ApplyTextDiff failed")
				return
			}
			if len(update) == 0 {
				return
			}
			if err := room.ApplyAndBroadcastFromFS(update); err != nil {
				log.Warn().Err(err).Msg("ApplyAndBroadcastFromFS failed")
			}
			return
		}

		// Cold path: no live room. Load doc, apply, persist, close.
		doc, err := crdtReg.LoadDoc(ctx, v.ID, n.ID)
		if err != nil {
			log.Warn().Err(err).Msg("LoadDoc failed")
			return
		}
		defer doc.Close()
		update, err := doc.ApplyTextDiff(newText, originKind)
		if err != nil {
			log.Warn().Err(err).Msg("cold ApplyTextDiff failed")
			return
		}
		if len(update) == 0 {
			return
		}
		if err := crdtReg.PersistChange(ctx, v.ID, n.ID, update, uuid.Nil, originKind, doc); err != nil {
			log.Warn().Err(err).Msg("PersistChange failed")
		}
		// Bump updated_at so list/search reflects the external edit.
		// We don't audit fs-watcher writes for now — the action is
		// attributed to the underlying user via their OS audit; future
		// slice could surface them via a "system" actor.
		updated := n
		updated.UpdatedAt = time.Now().UTC()
		_ = noteStore.Upsert(ctx, updated)
	})
}

// ---------------------------------------------------------- middleware ------

func securityHeaders() fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Set("X-Frame-Options", "DENY")
		c.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()")
		return c.Next()
	}
}

func corsMiddleware(allowed []string) fiber.Handler {
	allowSet := make(map[string]struct{}, len(allowed))
	for _, o := range allowed {
		allowSet[o] = struct{}{}
	}
	return func(c *fiber.Ctx) error {
		origin := c.Get("Origin")
		if origin != "" {
			if _, ok := allowSet[origin]; ok {
				c.Set("Access-Control-Allow-Origin", origin)
				c.Set("Vary", "Origin")
				c.Set("Access-Control-Allow-Credentials", "true")
				c.Set("Access-Control-Expose-Headers", "X-Request-ID")
			}
		}
		if c.Method() == fiber.MethodOptions {
			c.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
			c.Set("Access-Control-Allow-Headers", "X-Lumi-Token, Authorization, Content-Type, X-Request-ID")
			c.Set("Access-Control-Max-Age", "600")
			return c.SendStatus(fiber.StatusNoContent)
		}
		return c.Next()
	}
}

func accessLog(zlog zerolog.Logger) fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()
		err := c.Next()
		evt := zlog.Info()
		if err != nil {
			evt = zlog.Warn().Err(err)
		}
		evt.
			Str("method", c.Method()).
			Str("path", c.Path()).
			Int("status", c.Response().StatusCode()).
			Int("bytes", len(c.Response().Body())).
			Dur("duration", time.Since(start)).
			Str("ip", c.IP()).
			Str("request_id", c.Get("X-Request-ID")).
			Msg("http_request")
		return err
	}
}

// --------------------------------------------------------- migrate cmd ------

func migrateCmd(args []string) int {
	_ = godotenv.Load()
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		return exitConfig
	}
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "migrate: subcommand required (up|down|status)")
		return exitUsage
	}
	src := "file://" + migrationsDir()
	m, err := migrate.New(src, cfg.databaseURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate init: %v\n", err)
		return exitMigrate
	}
	defer func() {
		_, _ = m.Close()
	}()

	switch args[0] {
	case "up":
		if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			fmt.Fprintf(os.Stderr, "migrate up: %v\n", err)
			return exitMigrate
		}
		fmt.Println("migrate up: ok")
		return exitOK
	case "down":
		if len(args) < 2 {
			fmt.Fprintln(os.Stderr, "migrate down: N required")
			return exitUsage
		}
		n, err := strconv.Atoi(args[1])
		if err != nil || n < 1 {
			fmt.Fprintln(os.Stderr, "migrate down: N must be a positive integer")
			return exitUsage
		}
		if err := m.Steps(-n); err != nil {
			fmt.Fprintf(os.Stderr, "migrate down: %v\n", err)
			return exitMigrate
		}
		fmt.Printf("migrate down %d: ok\n", n)
		return exitOK
	case "status":
		v, dirty, err := m.Version()
		if err != nil && !errors.Is(err, migrate.ErrNilVersion) {
			fmt.Fprintf(os.Stderr, "migrate status: %v\n", err)
			return exitMigrate
		}
		if errors.Is(err, migrate.ErrNilVersion) {
			fmt.Println("version=0 dirty=false")
			return exitOK
		}
		fmt.Printf("version=%d dirty=%v\n", v, dirty)
		return exitOK
	default:
		fmt.Fprintf(os.Stderr, "migrate: unknown subcommand %q\n", args[0])
		return exitUsage
	}
}

func migrationsDir() string {
	if d := os.Getenv("LUMI_MIGRATIONS_DIR"); d != "" {
		return d
	}
	return "migrations"
}
