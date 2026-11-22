package feed

import (
	"bufio"
	"math"
	"strconv"

	"github.com/gofiber/fiber/v2"

	"github.com/ViniZap4/lumi-server/internal/auth"
)

// capRetryAfterSeconds is the Retry-After sent with 429 too_many_streams.
const capRetryAfterSeconds = 30

// Handler serves GET /api/events.
type Handler struct {
	broker *Broker
}

func NewHandler(b *Broker) *Handler { return &Handler{broker: b} }

// Register mounts the stream on the AUTHENTICATED /api group. The route is
// not in auth's query-token allow-list, so the token must come in the
// Authorization (Bearer) or X-Lumi-Token header; a ?token= alone is
// ignored and answers 401.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/events", h.stream)
}

// stream — GET /api/events
//
// Response: 200 text/event-stream; first event is always `hello`. No `id:`
// lines, Last-Event-ID ignored, no replay (SPEC-LIVROS §3.2).
//
// Errors: 401 (auth middleware), 429 {"error":"too_many_streams"} +
// Retry-After: 30 past 16 concurrent streams, 429 {"error":"rate_limited"} + Retry-After past 20
// opens per minute, 503 {"error":"shutting_down"} during shutdown.
func (h *Handler) stream(c *fiber.Ctx) error {
	user := auth.UserFromCtx(c)
	token := auth.ExtractToken(c)
	if user == nil || token == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	sub, err := h.broker.Open(user.ID, token)
	if err != nil {
		switch e := err.(type) {
		case *RateLimitError:
			secs := int(math.Ceil(e.RetryAfter.Seconds()))
			c.Set(fiber.HeaderRetryAfter, strconv.Itoa(max(secs, 1)))
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{"error": "rate_limited"})
		}
		switch err {
		case ErrTooManyStreams:
			// A slot frees when another stream of this user ends.
			c.Set(fiber.HeaderRetryAfter, strconv.Itoa(capRetryAfterSeconds))
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{"error": "too_many_streams"})
		case ErrClosed:
			c.Set(fiber.HeaderRetryAfter, "1")
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{"error": "shutting_down"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal"})
	}

	c.Set(fiber.HeaderContentType, "text/event-stream")
	c.Set(fiber.HeaderCacheControl, "no-store")
	c.Set("X-Accel-Buffering", "no")
	conn := c.Context().Conn()
	grace := h.broker.cfg.WriteGrace
	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		h.broker.Serve(sub, newFrameWriter(w, conn, grace))
	})
	return nil
}
