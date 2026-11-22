package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/rs/zerolog"

	"github.com/ViniZap4/lumi-server/internal/federation"
	"github.com/ViniZap4/lumi-server/internal/invites"
)

// TestRegisterRoutes_PublicRoutesBypassAuth is the regression test for the
// route-order bug: the authed /api group used to be created before the
// public invite/federation routes, so Fiber's prefix-scoped group
// middleware answered 401 to peer servers and invite recipients.
//
// The real handler structs are mounted with nil services; a request that
// reaches a handler either fails validation (4xx != 401) or panics into the
// recover middleware (500). Either way it proves the auth middleware did not
// intercept it. Protected routes must still be 401.
func TestRegisterRoutes_PublicRoutesBypassAuth(t *testing.T) {
	app := fiber.New()
	app.Use(recover.New())

	authCalls := 0
	requireAuth := func(c *fiber.Ctx) error {
		authCalls++
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	invH := invites.NewHandlers(nil)
	fedH := federation.NewHandlers(nil, nil)
	relayH := federation.NewRelayHandlers(nil, nil, zerolog.Nop())

	registerRoutes(app, requireAuth,
		[]func(fiber.Router){invH.RegisterPublic, fedH.RegisterPublic, relayH.Register},
		[]func(fiber.Router){
			func(r fiber.Router) { invH.RegisterAuthed(r, nil) },
			fedH.RegisterAuthed,
		},
	)

	cases := []struct {
		name       string
		method     string
		path       string
		wantAuthed bool
	}{
		{"invite info", http.MethodGet, "/api/invites/abc", false},
		{"invite accept", http.MethodPost, "/api/invites/abc/accept", false},
		{"federation identity", http.MethodGet, "/api/federation/identity", false},
		{"federation accept", http.MethodPost, "/api/federation/accept", false},
		{"federation sync challenge", http.MethodPost, "/api/federation/sync-challenge", false},
		{"federation relay ws", http.MethodGet, "/api/federation/vaults/00000000-0000-0000-0000-000000000001/sync", false},

		{"create invite", http.MethodPost, "/api/vaults/v1/invites", true},
		{"list invites", http.MethodGet, "/api/vaults/v1/invites", true},
		{"federation join", http.MethodPost, "/api/federation/join", true},
		{"federation invites", http.MethodPost, "/api/vaults/v1/federation-invites", true},
		{"unknown api route", http.MethodGet, "/api/does-not-exist", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := authCalls
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader("{}"))
			req.Header.Set("Content-Type", "application/json")
			resp, err := app.Test(req, -1)
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}
			ranAuth := authCalls > before
			if tc.wantAuthed {
				if resp.StatusCode != fiber.StatusUnauthorized || !ranAuth {
					t.Fatalf("protected route: status=%d ranAuth=%v, want 401 via auth middleware", resp.StatusCode, ranAuth)
				}
				return
			}
			if resp.StatusCode == fiber.StatusUnauthorized || ranAuth {
				t.Fatalf("public route: status=%d ranAuth=%v, want handler reached without auth", resp.StatusCode, ranAuth)
			}
		})
	}
}

// The WS sync route authenticates itself (close codes 4401/4403/4404), so
// it is mounted with the public routes; the auth middleware must not answer
// it with HTTP 401 (which browsers surface as an opaque 1006).
func TestRegisterRoutes_SyncRouteBypassesAuthMiddleware(t *testing.T) {
	app := fiber.New()
	authCalls := 0
	requireAuth := func(c *fiber.Ctx) error {
		authCalls++
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	sync := func(r fiber.Router) {
		r.Group("/api").Get("/vaults/:vault/notes/:id/sync", func(c *fiber.Ctx) error {
			return c.SendStatus(fiber.StatusUpgradeRequired)
		})
	}
	registerRoutes(app, requireAuth, []func(fiber.Router){sync}, []func(fiber.Router){
		func(r fiber.Router) { r.Get("/vaults/:vault/notes", func(c *fiber.Ctx) error { return nil }) },
	})
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/api/vaults/v/notes/n/sync", nil), -1)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != fiber.StatusUpgradeRequired || authCalls != 0 {
		t.Fatalf("status=%d authCalls=%d, want 426 without auth middleware", resp.StatusCode, authCalls)
	}
}
