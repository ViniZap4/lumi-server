package publish

import (
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/ViniZap4/lumi-server/internal/metrics"
)

// Rate limits (§A15.2).
const (
	PerIPPerMinute   = 60
	PerBookPerMinute = 10_000
)

// Handlers is the anonymous HTTP surface.
type Handlers struct {
	svc   *Service
	ipRL  *windowLimiter
	bkRL  *windowLimiter
	clock func() time.Time
	// ClientIP keys the per-IP limit (c.IP() by default; set it when
	// the server sits behind a trusted proxy).
	ClientIP func(*fiber.Ctx) string
}

func NewHandlers(svc *Service) *Handlers {
	return &Handlers{
		svc:      svc,
		ipRL:     newWindowLimiter(PerIPPerMinute, time.Minute),
		bkRL:     newWindowLimiter(PerBookPerMinute, time.Minute),
		clock:    time.Now,
		ClientIP: func(c *fiber.Ctx) string { return c.IP() },
	}
}

// Register attaches the public routes. Like every unauthenticated route
// it must be registered before the authenticated /api group.
func (h *Handlers) Register(r fiber.Router) {
	r.Get("/api/public/books/:slug", h.book)
	r.Get("/api/public/books/:slug/notes/:id", h.note)
}

// publicHeaders: cacheable, no cookies, nothing executable, no referrer.
func publicHeaders(c *fiber.Ctx) {
	c.Set(fiber.HeaderCacheControl, "public, max-age=60")
	c.Set(fiber.HeaderContentSecurityPolicy, "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'; sandbox")
	c.Set(fiber.HeaderXContentTypeOptions, "nosniff")
	c.Set(fiber.HeaderReferrerPolicy, "no-referrer")
	c.Set("Cross-Origin-Resource-Policy", "cross-origin")
	c.Response().Header.Del(fiber.HeaderSetCookie)
}

func (h *Handlers) answer(c *fiber.Ctx, status int, body any) error {
	metrics.PublishRequests.With(strconv.Itoa(status)).Inc()
	if status >= 400 {
		// Errors are not cached by shared caches for long.
		c.Set(fiber.HeaderCacheControl, "no-store")
	}
	return c.Status(status).JSON(body)
}

func (h *Handlers) notFound(c *fiber.Ctx) error {
	return h.answer(c, fiber.StatusNotFound, fiber.Map{"error": "not_found"})
}

// guard applies the per-IP limit and resolves the book (per-book limit).
func (h *Handlers) guard(c *fiber.Ctx) (Book, bool, error) {
	publicHeaders(c)
	c.Set("X-Robots-Tag", "noindex, nofollow")
	now := h.clock()
	if ok, wait := h.ipRL.allow(h.ClientIP(c), now); !ok {
		return Book{}, false, h.limited(c, wait)
	}
	b, err := h.svc.Resolve(c.UserContext(), c.Params("slug"))
	switch {
	case errors.Is(err, ErrGone):
		return Book{}, false, h.answer(c, fiber.StatusGone, fiber.Map{"error": "gone"})
	case err != nil:
		return Book{}, false, h.notFound(c)
	}
	if ok, wait := h.bkRL.allow(b.VaultID.String(), now); !ok {
		return Book{}, false, h.limited(c, wait)
	}
	if b.Robots == "" {
		c.Response().Header.Del("X-Robots-Tag")
	} else {
		c.Set("X-Robots-Tag", b.Robots)
	}
	return b, true, nil
}

func (h *Handlers) limited(c *fiber.Ctx, wait time.Duration) error {
	secs := int((wait + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	c.Set(fiber.HeaderRetryAfter, strconv.Itoa(secs))
	return h.answer(c, fiber.StatusTooManyRequests, fiber.Map{"error": "rate_limited", "retry_after": secs})
}

func (h *Handlers) book(c *fiber.Ctx) error {
	b, ok, err := h.guard(c)
	if !ok {
		return err
	}
	notes, err := h.svc.List(c.UserContext(), b)
	if err != nil {
		return h.answer(c, fiber.StatusServiceUnavailable, fiber.Map{"error": "unavailable"})
	}
	return h.answer(c, fiber.StatusOK, fiber.Map{"name": b.Name, "notes": notes})
}

func (h *Handlers) note(c *fiber.Ctx) error {
	b, ok, err := h.guard(c)
	if !ok {
		return err
	}
	n, err := h.svc.Note(c.UserContext(), b, c.Params("id"))
	if err != nil {
		return h.notFound(c)
	}
	return h.answer(c, fiber.StatusOK, n)
}

// windowLimiter is a fixed-window counter per key, swept as it goes.
type windowLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	m      map[string]*window
	swept  time.Time
}

type window struct {
	start time.Time
	n     int
}

func newWindowLimiter(limit int, d time.Duration) *windowLimiter {
	return &windowLimiter{limit: limit, window: d, m: map[string]*window{}}
}

func (l *windowLimiter) allow(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.swept) > l.window {
		for k, w := range l.m {
			if now.Sub(w.start) >= l.window {
				delete(l.m, k)
			}
		}
		l.swept = now
	}
	w := l.m[key]
	if w == nil || now.Sub(w.start) >= l.window {
		w = &window{start: now}
		l.m[key] = w
	}
	if w.n >= l.limit {
		return false, w.start.Add(l.window).Sub(now)
	}
	w.n++
	return true, 0
}
