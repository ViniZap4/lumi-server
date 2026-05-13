// Audit log read API. Writes happen across the codebase via the Recorder
// interface; this file exposes the inverse — a paginated read endpoint for
// vault-scoped audit entries, guarded by the audit.read capability.
//
// SPEC.md lists `GET /api/vaults/:vault/audit` under the v2 surface; this
// handler completes that surface for Phase 1. Phase 2 (notes/CRDT) will add
// more audit actions but doesn't change this endpoint's shape.

package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/capguard"
	"github.com/ViniZap4/lumi-server/internal/domain"
)

// Lister reads vault-scoped audit entries. pg.AuditStore satisfies this; tests
// can drop in a fake without dragging in the whole storage layer.
type Lister interface {
	ListForVault(ctx context.Context, vaultID uuid.UUID, limit, offset int) ([]domain.AuditEntry, error)
}

// Handlers serves the audit read endpoints.
type Handlers struct {
	store    Lister
	resolver capguard.Resolver
}

// NewHandlers wires a Handlers around a Lister + capability resolver.
func NewHandlers(store Lister, resolver capguard.Resolver) *Handlers {
	return &Handlers{store: store, resolver: resolver}
}

// Register attaches GET /api/vaults/:vault/audit to the authed group.
func (h *Handlers) Register(r fiber.Router) {
	r.Get("/vaults/:vault/audit",
		capguard.RequireCapability(h.resolver, domain.CapAuditRead),
		h.list,
	)
}

// Pagination defaults / caps. Mirror the practical sizes other paginated
// surfaces use; large pages are wasteful for an audit feed that's typically
// browsed top-down.
const (
	defaultLimit = 50
	maxLimit     = 200
)

type auditDTO struct {
	ID        int64           `json:"id"`
	UserID    *string         `json:"user_id"`
	VaultID   *string         `json:"vault_id"`
	Action    string          `json:"action"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	IP        *string         `json:"ip,omitempty"`
	UserAgent *string         `json:"user_agent,omitempty"`
	CreatedAt string          `json:"created_at"`
}

func (h *Handlers) list(c *fiber.Ctx) error {
	vaultID, err := capguard.WithVaultID(c)
	if err != nil {
		return nil
	}
	limit, offset := parsePagination(c)

	entries, err := h.store.ListForVault(c.UserContext(), vaultID, limit, offset)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "internal"})
	}

	out := make([]auditDTO, 0, len(entries))
	for _, e := range entries {
		out = append(out, toDTO(e))
	}
	return c.JSON(fiber.Map{
		"entries": out,
		"limit":   limit,
		"offset":  offset,
	})
}

func parsePagination(c *fiber.Ctx) (limit, offset int) {
	limit = defaultLimit
	if raw := c.Query("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	if raw := c.Query("offset"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
			offset = n
		}
	}
	return
}

func toDTO(e domain.AuditEntry) auditDTO {
	d := auditDTO{
		ID:        e.ID,
		Action:    e.Action,
		IP:        e.IP,
		UserAgent: e.UserAgent,
		CreatedAt: e.CreatedAt.UTC().Format(time.RFC3339Nano),
	}
	if e.UserID != nil {
		s := e.UserID.String()
		d.UserID = &s
	}
	if e.VaultID != nil {
		s := e.VaultID.String()
		d.VaultID = &s
	}
	if len(e.Payload) > 0 && json.Valid(e.Payload) {
		d.Payload = append(d.Payload, e.Payload...)
	}
	return d
}
