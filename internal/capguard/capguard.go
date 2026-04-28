// Package capguard centralises the "does this user have this capability in
// this vault" check. It lives in its own package so roles, members, notes,
// invites, and audit handlers all reuse the same logic without importing
// each other.
//
// On a denial we always respond with the same shape:
//
//	{ "error": "capability_missing", "capability": "<cap>" }
//
// — clients use that string to render targeted UI.
package capguard

import (
	"context"
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// userIDKey is the locals key set by the auth middleware once the bearer
// session is resolved.
const userIDKey = "lumi.user_id"

// Resolver returns the role a user holds within a vault. Returns
// domain.ErrNotFound when the user is not a member.
type Resolver interface {
	RoleForUser(ctx context.Context, vaultID, userID uuid.UUID) (domain.Role, error)
}

// Require enforces that the authenticated caller holds cap inside vaultID.
// On denial it writes a 403 JSON body and returns domain.ErrForbidden so
// callers can short-circuit. Membership absence is mapped to forbidden
// (not 404) to avoid leaking which vault IDs exist on the server.
func Require(c *fiber.Ctx, r Resolver, vaultID uuid.UUID, cap domain.Capability) error {
	uid, ok := UserIDFrom(c)
	if !ok {
		return respondForbidden(c, cap)
	}
	role, err := r.RoleForUser(c.UserContext(), vaultID, uid)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return respondForbidden(c, cap)
		}
		return err
	}
	if !role.Capabilities.Has(cap) {
		return respondForbidden(c, cap)
	}
	return nil
}

// RequireMembership checks only that the caller is a member. Used for
// endpoints that any member may read.
func RequireMembership(c *fiber.Ctx, r Resolver, vaultID uuid.UUID) error {
	uid, ok := UserIDFrom(c)
	if !ok {
		return respondForbidden(c, "")
	}
	if _, err := r.RoleForUser(c.UserContext(), vaultID, uid); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return respondForbidden(c, "")
		}
		return err
	}
	return nil
}

// WithVaultID parses the `:vault` URL parameter as a UUID. Returns 400 JSON
// on failure.
func WithVaultID(c *fiber.Ctx) (uuid.UUID, error) {
	raw := c.Params("vault")
	id, err := uuid.Parse(raw)
	if err != nil {
		_ = c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "invalid_vault_id",
			"message": "vault path parameter must be a valid UUID",
		})
		return uuid.Nil, domain.ErrValidation
	}
	return id, nil
}

// WithUserID parses the `:user` URL parameter as a UUID.
func WithUserID(c *fiber.Ctx) (uuid.UUID, error) {
	raw := c.Params("user")
	id, err := uuid.Parse(raw)
	if err != nil {
		_ = c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":   "invalid_user_id",
			"message": "user path parameter must be a valid UUID",
		})
		return uuid.Nil, domain.ErrValidation
	}
	return id, nil
}

// UserIDFrom retrieves the authenticated user id placed in fiber.Locals by
// the auth middleware.
func UserIDFrom(c *fiber.Ctx) (uuid.UUID, bool) {
	v := c.Locals(userIDKey)
	if v == nil {
		return uuid.Nil, false
	}
	switch t := v.(type) {
	case uuid.UUID:
		return t, true
	case string:
		id, err := uuid.Parse(t)
		if err != nil {
			return uuid.Nil, false
		}
		return id, true
	default:
		return uuid.Nil, false
	}
}

// SetUserID stores the authenticated user id in fiber.Locals. The auth
// middleware should call this once the session is validated.
func SetUserID(c *fiber.Ctx, id uuid.UUID) {
	c.Locals(userIDKey, id)
}

// RequireCapability is a middleware factory: builds a fiber.Handler that
// enforces cap on the vault id parsed from the URL.
func RequireCapability(r Resolver, cap domain.Capability) fiber.Handler {
	return func(c *fiber.Ctx) error {
		vid, err := WithVaultID(c)
		if err != nil {
			return nil
		}
		if err := Require(c, r, vid, cap); err != nil {
			return nil
		}
		return c.Next()
	}
}

func respondForbidden(c *fiber.Ctx, cap domain.Capability) error {
	body := fiber.Map{"error": "capability_missing"}
	if cap != "" {
		body["capability"] = string(cap)
	}
	_ = c.Status(fiber.StatusForbidden).JSON(body)
	return domain.ErrForbidden
}
