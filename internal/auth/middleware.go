package auth

import (
	"context"
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/ViniZap4/lumi-server/internal/capguard"
	"github.com/ViniZap4/lumi-server/internal/domain"
)

const (
	HeaderToken      = "X-Lumi-Token"
	HeaderAuthBearer = "Authorization"
	QueryToken       = "token"
)

// queryTokenPathPrefixes is the allow-list for ?token= fallback. Anywhere
// else a query-string token is ignored to prevent leakage via referer/log.
var queryTokenPathPrefixes = []string{
	"/api/files/",
	"/ws",
}

// Required returns a middleware that demands a valid session.
func Required(svc *Service) fiber.Handler {
	if svc == nil {
		panic("auth: Required called with nil Service")
	}
	return func(c *fiber.Ctx) error {
		token := extractToken(c)
		if token == "" {
			return unauthorized(c)
		}
		sess, user, err := svc.Validate(c.UserContext(), token)
		if err != nil {
			return mapValidateErr(c, err)
		}
		bind(c, sess, user)
		return c.Next()
	}
}

// Optional attaches user/session if present, but does not error on miss.
func Optional(svc *Service) fiber.Handler {
	if svc == nil {
		panic("auth: Optional called with nil Service")
	}
	return func(c *fiber.Ctx) error {
		token := extractToken(c)
		if token == "" {
			return c.Next()
		}
		sess, user, err := svc.Validate(c.UserContext(), token)
		if err != nil {
			return c.Next()
		}
		bind(c, sess, user)
		return c.Next()
	}
}

func extractToken(c *fiber.Ctx) string {
	if t := strings.TrimSpace(c.Get(HeaderToken)); t != "" {
		return t
	}
	if a := strings.TrimSpace(c.Get(HeaderAuthBearer)); a != "" {
		const prefix = "Bearer "
		if len(a) > len(prefix) && strings.EqualFold(a[:len(prefix)], prefix) {
			return strings.TrimSpace(a[len(prefix):])
		}
	}
	if isQueryTokenAllowed(c.Path()) {
		if q := strings.TrimSpace(c.Query(QueryToken)); q != "" {
			return q
		}
	}
	return ""
}

func isQueryTokenAllowed(path string) bool {
	for _, prefix := range queryTokenPathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
		if prefix == "/ws" && (path == "/ws" || strings.HasPrefix(path, "/ws/") || strings.HasPrefix(path, "/ws?")) {
			return true
		}
	}
	return false
}

func bind(c *fiber.Ctx, sess domain.Session, user domain.User) {
	sCopy := sess
	uCopy := user
	c.Locals(ctxKeySession, &sCopy)
	c.Locals(ctxKeyUser, &uCopy)
	// Also publish to capguard so capability handlers can read the user id
	// without importing this package.
	capguard.SetUserID(c, user.ID)
}

func mapValidateErr(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, domain.ErrTokenExpired):
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "token_expired"})
	case errors.Is(err, domain.ErrTokenInvalid):
		return unauthorized(c)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "timeout"})
	default:
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal"})
	}
}

func unauthorized(c *fiber.Ctx) error {
	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
}
