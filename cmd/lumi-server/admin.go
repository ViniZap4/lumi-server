package main

// Server administration (docs/ADMIN.md): the admin listener started by the
// server, and the CLI subcommands that share its admin.Service.

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/ViniZap4/lumi-server/internal/admin"
	"github.com/ViniZap4/lumi-server/internal/auth"
	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/federation"
	"github.com/ViniZap4/lumi-server/internal/feed"
	"github.com/ViniZap4/lumi-server/internal/members"
	"github.com/ViniZap4/lumi-server/internal/storage/fs"
	"github.com/ViniZap4/lumi-server/internal/storage/pg"
	"github.com/ViniZap4/lumi-server/internal/users"
	"github.com/ViniZap4/lumi-server/internal/vaults"
	"github.com/ViniZap4/lumi-server/internal/wsync"
)

// adminConfig is the admin listener's configuration.
//
//	LUMI_ADMIN_ADDR             host:port of the admin listener; empty = off
//	LUMI_ADMIN_TRUSTED_PROXIES  CIDRs whose X-Forwarded-For is believed on
//	                            the admin listener only
type adminConfig struct {
	addr           string
	trustedProxies []netip.Prefix
}

func publicListenAddr(c config) string {
	return net.JoinHostPort(c.bindAddr, strconv.Itoa(c.port))
}

// loadAdminConfig reads the admin env and refuses an admin listener that
// would share the public API's address.
func loadAdminConfig(c config) (adminConfig, error) {
	ac := adminConfig{addr: os.Getenv("LUMI_ADMIN_ADDR")}
	proxies, err := admin.ParseTrustedProxies(os.Getenv("LUMI_ADMIN_TRUSTED_PROXIES"))
	if err != nil {
		return adminConfig{}, fmt.Errorf("%w: LUMI_ADMIN_TRUSTED_PROXIES: %v", domain.ErrValidation, err)
	}
	ac.trustedProxies = proxies
	if ac.addr == "" {
		return ac, nil
	}
	if err := admin.ValidateListenAddr(ac.addr); err != nil {
		return adminConfig{}, fmt.Errorf("%w: LUMI_ADMIN_ADDR %v", domain.ErrValidation, err)
	}
	if admin.SameListener(ac.addr, publicListenAddr(c)) {
		return adminConfig{}, fmt.Errorf("%w: LUMI_ADMIN_ADDR %q must differ from the public listener %q (LUMI_BIND_ADDR:LUMI_PORT): the admin API never shares the public port",
			domain.ErrValidation, ac.addr, publicListenAddr(c))
	}
	return ac, nil
}

// adminLive is what the running server hands the admin API: the same
// services the public API uses, so admin actions take effect at once.
type adminLive struct {
	auth       *auth.Service
	users      *users.Service
	vaults     *vaults.Service
	federation *federation.Service
	broker     *feed.Broker
	hub        *wsync.Hub
}

type adminConns struct {
	broker *feed.Broker
	hub    *wsync.Hub
}

func (c adminConns) FeedStreams() int   { return c.broker.TotalStreams() }
func (c adminConns) WSConnections() int { return c.hub.TotalConnections() }

// startAdmin binds the admin listener (when LUMI_ADMIN_ADDR is set) and
// serves it in the background. The returned func shuts it down.
func startAdmin(ctx context.Context, cfg config, zlog zerolog.Logger, pool *pgxpool.Pool, live adminLive) (shutdownFn, error) {
	noop := func(context.Context) error { return nil }
	if cfg.admin.addr == "" {
		return noop, nil
	}
	log := zlog // admin events carry component=admin themselves
	svc := &admin.Service{
		Store:         pg.NewAdminStore(pool),
		Users:         live.users,
		Vaults:        live.vaults,
		Federations:   live.federation,
		Hasher:        live.auth,
		Login:         live.auth,
		Live:          live.broker,
		Log:           log,
		Version:       Version,
		MigrationsDir: migrationsDir(),
	}
	limiter := admin.NewFailureLimiter(10, 6*time.Second, 10_000)
	api := &admin.HTTP{
		Service:        svc,
		Limiter:        limiter,
		TrustedProxies: cfg.admin.trustedProxies,
		Conns:          adminConns{broker: live.broker, hub: live.hub},
		StartedAt:      time.Now(),
		Log:            log,
		AppName:        "lumi-server admin " + Version,
	}
	app := api.App()

	ln, err := net.Listen("tcp", cfg.admin.addr)
	if err != nil {
		return nil, fmt.Errorf("admin listener: %w", err)
	}
	if !admin.LoopbackOnly(cfg.admin.addr) {
		log.Warn().Str("component", "admin").Str("addr", cfg.admin.addr).
			Msg("the admin API listens beyond loopback without TLS: admin tokens cross the network in clear text; keep it on a private network (e.g. the internal compose network, no published port)")
	}
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				limiter.Sweep()
			}
		}
	}()
	go func() {
		log.Info().Str("component", "admin").Str("addr", ln.Addr().String()).Msg("admin API listening")
		if err := app.Listener(ln); err != nil {
			log.Error().Str("component", "admin").Err(err).Msg("admin listener exited")
		}
	}()
	return func(ctx context.Context) error { return app.ShutdownWithContext(ctx) }, nil
}

// buildCLIAdmin wires the admin.Service for the CLI from the database and
// the vault root, with the same services the server uses minus the live
// parts (feed, WS hub, relay links): their effects arrive at the running
// server's next periodic re-check or reconnect, which the CLI points out.
func buildCLIAdmin(ctx context.Context, cfg config, zlog zerolog.Logger, pool *pgxpool.Pool, fsMgr *fs.Manager) (*admin.Service, error) {
	userStore := pg.NewUserStore(pool)
	consentStore := pg.NewConsentStore(pool)
	auditStore := pg.NewAuditStore(pool)
	vaultStore := pg.NewVaultStore(pool)
	roleStore := pg.NewRoleStore(pool)
	memberStore := pg.NewMemberStore(pool)
	fedStore := pg.NewFederationStore(pool)

	membersSvc := members.NewService(memberRepoAdapter{memberStore}, auditStore)
	membersSvc.SetVaultLookup(vaultStore)
	membersSvc.SetRoleLookup(roleStore)
	fedResolver := federation.NewControlResolver(membersSvc, userStore)
	membersSvc.SetGrantResolver(fedResolver)
	vaultsSvc := vaults.NewService(vaultStore, roleStore, memberStore, fsMgr, auditStore, fedResolver)

	fedSvc, err := federation.NewService(ctx, federation.Deps{
		Keys:        pg.NewServerKeyStore(pool),
		Federations: fedStore,
		Invites:     pg.NewFederationInviteStore(pool),
		Vaults:      vaultStore,
		Creator:     vaultsSvc,
		Audit:       auditStore,
		BaseURL:     cfg.publicBaseURL,
		Net:         cfg.federationNet,
	})
	if err != nil {
		return nil, fmt.Errorf("federation service: %w", err)
	}
	// Control plane without a pusher: rebuilt states are persisted and
	// reach followers when their link (re)connects.
	fedSvc.SetControlPlane(federation.ControlPlaneDeps{
		States:     pg.NewControlStateStore(pool),
		Replicated: pg.NewReplicatedControlStore(pool),
		FedMembers: fedMemberAdapter{pg.NewFederatedMemberStore(pool)},
		Members:    membersSvc,
		Roles:      roleStore,
		Acks:       fedStore,
	})
	fedResolver.Bind(fedSvc)

	usersSvc := users.NewService(userStore, consentStore, auditStore, auditStore, vaultStore)
	usersSvc.SetVaultDirRemover(fsMgr)
	usersSvc.SetFederationLister(fedStore)
	usersSvc.SetControlNotifier(syncControl{svc: fedSvc, log: zlog})

	return &admin.Service{
		Store:         pg.NewAdminStore(pool),
		Users:         usersSvc,
		Vaults:        vaultsSvc,
		Federations:   fedSvc,
		Hasher:        bcryptHasher{},
		Log:           zlog,
		Version:       Version,
		MigrationsDir: migrationsDir(),
	}, nil
}

// syncControl rebuilds a vault's federation control state before the CLI
// exits (the server's notifier does it asynchronously).
type syncControl struct {
	svc *federation.Service
	log zerolog.Logger
}

func (s syncControl) ControlChanged(vaultID uuid.UUID) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, _, _, err := s.svc.RebuildControlState(ctx, vaultID); err != nil {
		s.log.Warn().Err(err).Str("vault_id", vaultID.String()).Msg("rebuild federation control state")
	}
}

// bcryptHasher hashes like auth.Service with the server's cost.
type bcryptHasher struct{}

func (bcryptHasher) HashPassword(pw string) (string, error) {
	return auth.HashPassword(pw, serverBcryptCost)
}

// serverBcryptCost must match auth.Config.BcryptCost in buildApp.
const serverBcryptCost = 12
