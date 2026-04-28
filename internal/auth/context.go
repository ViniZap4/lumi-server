package auth

import (
	"github.com/gofiber/fiber/v2"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

const (
	ctxKeyUser    = "auth.user"
	ctxKeySession = "auth.session"
)

// UserFromCtx extracts the authenticated user attached by Required /
// Optional middleware.
func UserFromCtx(c *fiber.Ctx) *domain.User {
	v := c.Locals(ctxKeyUser)
	if v == nil {
		return nil
	}
	u, ok := v.(*domain.User)
	if !ok {
		return nil
	}
	return u
}

// SessionFromCtx extracts the authenticated session.
func SessionFromCtx(c *fiber.Ctx) *domain.Session {
	v := c.Locals(ctxKeySession)
	if v == nil {
		return nil
	}
	s, ok := v.(*domain.Session)
	if !ok {
		return nil
	}
	return s
}
