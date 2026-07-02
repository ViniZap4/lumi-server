package federation

import (
	"errors"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/capguard"
	"github.com/ViniZap4/lumi-server/internal/domain"
)

type Handlers struct {
	svc      *Service
	resolver capguard.Resolver
}

func NewHandlers(svc *Service, resolver capguard.Resolver) *Handlers {
	return &Handlers{svc: svc, resolver: resolver}
}

// Register wires public server-to-server routes on the app and operator/admin
// routes on the authed group (mirrors the invites package split).
func (h *Handlers) Register(app *fiber.App, authed fiber.Router) {
	app.Get("/api/federation/identity", h.identity)
	app.Post("/api/federation/accept", h.accept)

	authed.Post("/federation/join", h.join)
	authed.Post("/vaults/:vault/federation-invites",
		capguard.RequireCapability(h.resolver, domain.CapVaultFederate), h.createInvite)
	authed.Get("/vaults/:vault/federation-invites",
		capguard.RequireCapability(h.resolver, domain.CapVaultFederate), h.listInvites)
	authed.Delete("/vaults/:vault/federation-invites/:token",
		capguard.RequireCapability(h.resolver, domain.CapVaultFederate), h.revokeInvite)
	authed.Get("/vaults/:vault/federations", h.listFederations)
	authed.Delete("/vaults/:vault/federations/:id",
		capguard.RequireCapability(h.resolver, domain.CapVaultFederate), h.revokeFederation)
}

// ---- public --------------------------------------------------------------------

func (h *Handlers) identity(c *fiber.Ctx) error {
	ident, err := h.svc.Identity()
	if err != nil {
		return mapErr(c, err)
	}
	return c.JSON(ident)
}

func (h *Handlers) accept(c *fiber.Ctx) error {
	var req AcceptRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_body"})
	}
	resp, err := h.svc.Accept(c.UserContext(), req)
	if err != nil {
		return mapErr(c, err)
	}
	return c.Status(http.StatusCreated).JSON(resp)
}

// ---- authed --------------------------------------------------------------------

type joinReq struct {
	HomeURL      string `json:"home_url"`
	Token        string `json:"token"`
	Jurisdiction string `json:"jurisdiction,omitempty"`
}

func (h *Handlers) join(c *fiber.Ctx) error {
	actor, ok := capguard.UserIDFrom(c)
	if !ok {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	var req joinReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_body"})
	}
	replica, fed, err := h.svc.Join(c.UserContext(), JoinInput{
		HomeURL:      req.HomeURL,
		Token:        req.Token,
		Jurisdiction: req.Jurisdiction,
		Actor:        actor,
		IP:           c.IP(),
		UserAgent:    string(c.Request().Header.UserAgent()),
	})
	if err != nil {
		return mapErr(c, err)
	}
	return c.Status(http.StatusCreated).JSON(fiber.Map{
		"vault":      fiber.Map{"id": replica.ID, "slug": replica.Slug, "name": replica.Name},
		"federation": toFederationDTO(fed),
	})
}

type createInviteReq struct {
	ServerURLHint string     `json:"server_url_hint,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
}

func (h *Handlers) createInvite(c *fiber.Ctx) error {
	vid, err := capguard.WithVaultID(c)
	if err != nil {
		return nil
	}
	actor, ok := capguard.UserIDFrom(c)
	if !ok {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	var req createInviteReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_body"})
	}
	in := CreateInviteInput{
		VaultID:       vid,
		Actor:         actor,
		ServerURLHint: req.ServerURLHint,
		IP:            c.IP(),
		UserAgent:     string(c.Request().Header.UserAgent()),
	}
	if req.ExpiresAt != nil {
		in.ExpiresAt = *req.ExpiresAt
	}
	inv, err := h.svc.CreateInvite(c.UserContext(), in)
	if err != nil {
		return mapErr(c, err)
	}
	return c.Status(http.StatusCreated).JSON(toInviteDTO(inv))
}

func (h *Handlers) listInvites(c *fiber.Ctx) error {
	vid, err := capguard.WithVaultID(c)
	if err != nil {
		return nil
	}
	invs, err := h.svc.ListInvites(c.UserContext(), vid)
	if err != nil {
		return mapErr(c, err)
	}
	out := make([]fiber.Map, 0, len(invs))
	for _, inv := range invs {
		out = append(out, toInviteDTO(inv))
	}
	return c.JSON(fiber.Map{"invites": out})
}

func (h *Handlers) revokeInvite(c *fiber.Ctx) error {
	vid, err := capguard.WithVaultID(c)
	if err != nil {
		return nil
	}
	actor, _ := capguard.UserIDFrom(c)
	if err := h.svc.RevokeInvite(c.UserContext(), vid, c.Params("token"), actor, c.IP(), string(c.Request().Header.UserAgent())); err != nil {
		return mapErr(c, err)
	}
	return c.SendStatus(http.StatusNoContent)
}

func (h *Handlers) listFederations(c *fiber.Ctx) error {
	vid, err := capguard.WithVaultID(c)
	if err != nil {
		return nil
	}
	// LGPD member notice: every member may see where the vault's data goes,
	// so membership (not a capability) is the gate.
	if err := capguard.RequireMembership(c, h.resolver, vid); err != nil {
		return nil
	}
	feds, err := h.svc.ListFederations(c.UserContext(), vid)
	if err != nil {
		return mapErr(c, err)
	}
	out := make([]fiber.Map, 0, len(feds))
	for _, f := range feds {
		out = append(out, toFederationDTO(f))
	}
	return c.JSON(fiber.Map{"federations": out})
}

func (h *Handlers) revokeFederation(c *fiber.Ctx) error {
	vid, err := capguard.WithVaultID(c)
	if err != nil {
		return nil
	}
	fedID, err := uuid.Parse(c.Params("id"))
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_federation_id"})
	}
	actor, _ := capguard.UserIDFrom(c)
	if err := h.svc.RevokeFederation(c.UserContext(), vid, fedID, actor, c.IP(), string(c.Request().Header.UserAgent())); err != nil {
		return mapErr(c, err)
	}
	return c.SendStatus(http.StatusNoContent)
}

// ---- DTOs ----------------------------------------------------------------------

func toInviteDTO(inv domain.FederationInvite) fiber.Map {
	return fiber.Map{
		"token":           inv.Token,
		"vault_id":        inv.VaultID,
		"server_url_hint": inv.ServerURLHint,
		"expires_at":      inv.ExpiresAt.UTC().Format(time.RFC3339),
		"created_at":      inv.CreatedAt.UTC().Format(time.RFC3339),
		"used":            inv.UsedAt != nil,
		"revoked":         inv.RevokedAt != nil,
	}
}

func toFederationDTO(f domain.Federation) fiber.Map {
	out := fiber.Map{
		"id":         f.ID,
		"vault_id":   f.VaultID,
		"role":       f.Role,
		"peer_url":   f.PeerURL,
		"status":     f.Status,
		"created_at": f.CreatedAt.UTC().Format(time.RFC3339),
	}
	if f.Jurisdiction != nil {
		out["jurisdiction"] = *f.Jurisdiction
	}
	if f.RevokedAt != nil {
		out["revoked_at"] = f.RevokedAt.UTC().Format(time.RFC3339)
	}
	return out
}

func mapErr(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "not_found"})
	case errors.Is(err, domain.ErrValidation):
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "validation", "message": err.Error()})
	case errors.Is(err, domain.ErrConflict):
		return c.Status(http.StatusConflict).JSON(fiber.Map{"error": "conflict"})
	case errors.Is(err, domain.ErrForbidden):
		return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
	case errors.Is(err, domain.ErrUnauthorized):
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	default:
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "internal"})
	}
}
