// Package roles owns the per-vault role lifecycle: creation, update,
// deletion, listing. Seed roles (Admin/Editor/Viewer/Commenter) are
// inserted at vault creation by the storage layer's SeedForVault and
// protected from API mutation here.
package roles

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/audit"
	"github.com/ViniZap4/lumi-server/internal/capguard"
	"github.com/ViniZap4/lumi-server/internal/domain"
)

// Repo is the persistence boundary for vault_roles.
type Repo interface {
	Create(ctx context.Context, r domain.Role) (domain.Role, error)
	Get(ctx context.Context, vaultID, roleID uuid.UUID) (domain.Role, error)
	GetByName(ctx context.Context, vaultID uuid.UUID, name string) (domain.Role, error)
	ListForVault(ctx context.Context, vaultID uuid.UUID) ([]domain.Role, error)
	Update(ctx context.Context, r domain.Role) error
	Delete(ctx context.Context, vaultID, roleID uuid.UUID) error
	SeedForVault(ctx context.Context, vaultID uuid.UUID) ([]domain.Role, error)
	CountMembersWithRole(ctx context.Context, roleID uuid.UUID) (int, error)
	MembersWithRole(ctx context.Context, roleID uuid.UUID) ([]uuid.UUID, error)
}

// nameRe enforces the role-name grammar from SPEC.md.
var nameRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9 _-]{0,30}$`)

var knownCaps = map[domain.Capability]struct{}{
	domain.CapNoteRead:      {},
	domain.CapNoteCreate:    {},
	domain.CapNoteEdit:      {},
	domain.CapNoteDelete:    {},
	domain.CapNoteMove:      {},
	domain.CapMembersInvite: {},
	domain.CapMembersManage: {},
	domain.CapRolesManage:   {},
	domain.CapVaultManage:   {},
	domain.CapVaultExport:   {},
	domain.CapAuditRead:     {},
}

var knownWildcardPrefixes = map[string]struct{}{
	"note.":    {},
	"members.": {},
	"roles.":   {},
	"vault.":   {},
	"audit.":   {},
}

// Service is the business-logic layer.
type Service struct {
	repo  Repo
	audit audit.Recorder
}

func NewService(r Repo, a audit.Recorder) *Service {
	if a == nil {
		a = audit.Noop{}
	}
	return &Service{repo: r, audit: a}
}

func (s *Service) Get(ctx context.Context, vaultID, roleID uuid.UUID) (domain.Role, error) {
	return s.repo.Get(ctx, vaultID, roleID)
}

func (s *Service) List(ctx context.Context, vaultID uuid.UUID) ([]domain.Role, error) {
	return s.repo.ListForVault(ctx, vaultID)
}

// Create inserts a custom role. Seed names are reserved.
func (s *Service) Create(
	ctx context.Context,
	vaultID uuid.UUID,
	name string,
	caps domain.CapabilitySet,
	actorID uuid.UUID,
	ip, ua string,
) (domain.Role, error) {
	name = strings.TrimSpace(name)
	if err := validateName(name); err != nil {
		return domain.Role{}, err
	}
	if _, isSeed := domain.SeedRoles()[name]; isSeed {
		return domain.Role{}, fmt.Errorf("%w: %q is a reserved seed-role name", domain.ErrValidation, name)
	}
	if err := validateCapabilities(caps); err != nil {
		return domain.Role{}, err
	}
	role := domain.Role{
		VaultID:      vaultID,
		Name:         name,
		Capabilities: dedupeCaps(caps),
		IsSeed:       false,
	}
	created, err := s.repo.Create(ctx, role)
	if err != nil {
		return domain.Role{}, err
	}
	s.recordAudit(ctx, domain.ActionRoleCreate, actorID, vaultID, ip, ua, map[string]any{
		"role_id":      created.ID.String(),
		"role_name":    created.Name,
		"capabilities": created.Capabilities,
	})
	return created, nil
}

func (s *Service) Update(
	ctx context.Context,
	vaultID, roleID uuid.UUID,
	newName *string,
	newCaps *domain.CapabilitySet,
	actorID uuid.UUID,
	ip, ua string,
) error {
	current, err := s.repo.Get(ctx, vaultID, roleID)
	if err != nil {
		return err
	}
	if current.IsSeed {
		return domain.ErrSeedRoleProtected
	}
	if newName == nil && newCaps == nil {
		return fmt.Errorf("%w: nothing to update", domain.ErrValidation)
	}
	updated := current
	if newName != nil {
		n := strings.TrimSpace(*newName)
		if err := validateName(n); err != nil {
			return err
		}
		if _, isSeed := domain.SeedRoles()[n]; isSeed {
			return fmt.Errorf("%w: %q is a reserved seed-role name", domain.ErrValidation, n)
		}
		updated.Name = n
	}
	if newCaps != nil {
		if err := validateCapabilities(*newCaps); err != nil {
			return err
		}
		updated.Capabilities = dedupeCaps(*newCaps)
	}
	if err := s.repo.Update(ctx, updated); err != nil {
		return err
	}
	s.recordAudit(ctx, domain.ActionRoleUpdate, actorID, vaultID, ip, ua, map[string]any{
		"role_id":      updated.ID.String(),
		"role_name":    updated.Name,
		"capabilities": updated.Capabilities,
	})
	return nil
}

// Delete refuses if any member still holds the role.
func (s *Service) Delete(
	ctx context.Context,
	vaultID, roleID uuid.UUID,
	actorID uuid.UUID,
	ip, ua string,
) error {
	current, err := s.repo.Get(ctx, vaultID, roleID)
	if err != nil {
		return err
	}
	if current.IsSeed {
		return domain.ErrSeedRoleProtected
	}
	holders, err := s.repo.MembersWithRole(ctx, roleID)
	if err != nil {
		return err
	}
	if len(holders) > 0 {
		return &RoleInUseError{RoleID: roleID, Members: holders}
	}
	if err := s.repo.Delete(ctx, vaultID, roleID); err != nil {
		return err
	}
	s.recordAudit(ctx, domain.ActionRoleDelete, actorID, vaultID, ip, ua, map[string]any{
		"role_id":   current.ID.String(),
		"role_name": current.Name,
	})
	return nil
}

type RoleInUseError struct {
	RoleID  uuid.UUID
	Members []uuid.UUID
}

func (e *RoleInUseError) Error() string {
	return fmt.Sprintf("role %s is still assigned to %d member(s)", e.RoleID, len(e.Members))
}

func (e *RoleInUseError) Unwrap() error { return domain.ErrConflict }

func validateName(n string) error {
	if n == "" {
		return fmt.Errorf("%w: role name is required", domain.ErrValidation)
	}
	if !nameRe.MatchString(n) {
		return fmt.Errorf("%w: role name %q must match %s", domain.ErrValidation, n, nameRe.String())
	}
	return nil
}

func validateCapabilities(caps domain.CapabilitySet) error {
	if len(caps) == 0 {
		return fmt.Errorf("%w: at least one capability is required", domain.ErrValidation)
	}
	for _, c := range caps {
		if err := validateCapability(c); err != nil {
			return err
		}
	}
	return nil
}

func validateCapability(c domain.Capability) error {
	s := string(c)
	if s == "" {
		return fmt.Errorf("%w: empty capability string", domain.ErrValidation)
	}
	if s == "*" {
		return nil
	}
	if strings.HasSuffix(s, ".*") {
		prefix := strings.TrimSuffix(s, "*")
		if _, ok := knownWildcardPrefixes[prefix]; !ok {
			return fmt.Errorf("%w: unknown wildcard capability %q", domain.ErrValidation, s)
		}
		return nil
	}
	if _, ok := knownCaps[c]; !ok {
		return fmt.Errorf("%w: unknown capability %q", domain.ErrValidation, s)
	}
	return nil
}

func dedupeCaps(in domain.CapabilitySet) domain.CapabilitySet {
	seen := make(map[domain.Capability]struct{}, len(in))
	out := make(domain.CapabilitySet, 0, len(in))
	for _, c := range in {
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

func (s *Service) recordAudit(ctx context.Context, action string, userID, vaultID uuid.UUID, ip, ua string, payload map[string]any) {
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{}`)
	}
	entry := domain.AuditEntry{
		Action:  action,
		Payload: body,
	}
	if userID != uuid.Nil {
		uid := userID
		entry.UserID = &uid
	}
	if vaultID != uuid.Nil {
		vid := vaultID
		entry.VaultID = &vid
	}
	if ip != "" {
		entry.IP = &ip
	}
	if ua != "" {
		entry.UserAgent = &ua
	}
	_ = s.audit.Record(ctx, entry)
}

// IsSeedRoleProtected reports whether err wraps domain.ErrSeedRoleProtected.
func IsSeedRoleProtected(err error) bool { return errors.Is(err, domain.ErrSeedRoleProtected) }

// ---- Handlers --------------------------------------------------------------

type Handlers struct {
	svc      *Service
	resolver capguard.Resolver
}

func NewHandlers(svc *Service, resolver capguard.Resolver) *Handlers {
	return &Handlers{svc: svc, resolver: resolver}
}

func (h *Handlers) Register(r fiber.Router) {
	r.Get("/vaults/:vault/roles", h.list)
	r.Post("/vaults/:vault/roles",
		capguard.RequireCapability(h.resolver, domain.CapRolesManage),
		h.create,
	)
	r.Patch("/vaults/:vault/roles/:role",
		capguard.RequireCapability(h.resolver, domain.CapRolesManage),
		h.update,
	)
	r.Delete("/vaults/:vault/roles/:role",
		capguard.RequireCapability(h.resolver, domain.CapRolesManage),
		h.delete,
	)
}

type roleDTO struct {
	ID           uuid.UUID            `json:"id"`
	VaultID      uuid.UUID            `json:"vault_id"`
	Name         string               `json:"name"`
	Capabilities domain.CapabilitySet `json:"capabilities"`
	IsSeed       bool                 `json:"is_seed"`
}

func toDTO(r domain.Role) roleDTO {
	caps := r.Capabilities
	if caps == nil {
		caps = domain.CapabilitySet{}
	}
	return roleDTO{
		ID:           r.ID,
		VaultID:      r.VaultID,
		Name:         r.Name,
		Capabilities: caps,
		IsSeed:       r.IsSeed,
	}
}

func (h *Handlers) list(c *fiber.Ctx) error {
	vid, err := capguard.WithVaultID(c)
	if err != nil {
		return nil
	}
	if err := capguard.RequireMembership(c, h.resolver, vid); err != nil {
		return nil
	}
	roles, err := h.svc.List(c.UserContext(), vid)
	if err != nil {
		return mapError(c, err)
	}
	out := make([]roleDTO, 0, len(roles))
	for _, r := range roles {
		out = append(out, toDTO(r))
	}
	return c.Status(http.StatusOK).JSON(fiber.Map{"roles": out})
}

type createReq struct {
	Name         string               `json:"name"`
	Capabilities domain.CapabilitySet `json:"capabilities"`
}

func (h *Handlers) create(c *fiber.Ctx) error {
	vid, err := capguard.WithVaultID(c)
	if err != nil {
		return nil
	}
	var req createReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_body"})
	}
	actor, _ := capguard.UserIDFrom(c)
	role, err := h.svc.Create(c.UserContext(), vid, req.Name, req.Capabilities, actor, c.IP(), string(c.Request().Header.UserAgent()))
	if err != nil {
		return mapError(c, err)
	}
	return c.Status(http.StatusCreated).JSON(toDTO(role))
}

type updateReq struct {
	Name         *string               `json:"name,omitempty"`
	Capabilities *domain.CapabilitySet `json:"capabilities,omitempty"`
}

func (h *Handlers) update(c *fiber.Ctx) error {
	vid, err := capguard.WithVaultID(c)
	if err != nil {
		return nil
	}
	roleID, err := uuid.Parse(c.Params("role"))
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_role_id"})
	}
	var req updateReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_body"})
	}
	actor, _ := capguard.UserIDFrom(c)
	if err := h.svc.Update(c.UserContext(), vid, roleID, req.Name, req.Capabilities, actor, c.IP(), string(c.Request().Header.UserAgent())); err != nil {
		return mapError(c, err)
	}
	updated, err := h.svc.Get(c.UserContext(), vid, roleID)
	if err != nil {
		return mapError(c, err)
	}
	return c.Status(http.StatusOK).JSON(toDTO(updated))
}

func (h *Handlers) delete(c *fiber.Ctx) error {
	vid, err := capguard.WithVaultID(c)
	if err != nil {
		return nil
	}
	roleID, err := uuid.Parse(c.Params("role"))
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_role_id"})
	}
	actor, _ := capguard.UserIDFrom(c)
	if err := h.svc.Delete(c.UserContext(), vid, roleID, actor, c.IP(), string(c.Request().Header.UserAgent())); err != nil {
		var inUse *RoleInUseError
		if errors.As(err, &inUse) {
			return c.Status(http.StatusConflict).JSON(fiber.Map{
				"error":   "role_in_use",
				"role_id": inUse.RoleID,
				"members": inUse.Members,
				"message": "reassign listed members to a different role before deletion",
			})
		}
		return mapError(c, err)
	}
	return c.SendStatus(http.StatusNoContent)
}

func mapError(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, domain.ErrSeedRoleProtected):
		return c.Status(http.StatusForbidden).JSON(fiber.Map{
			"error":   "seed_role_protected",
			"message": err.Error(),
		})
	case errors.Is(err, domain.ErrValidation):
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error":   "validation_failed",
			"message": err.Error(),
		})
	case errors.Is(err, domain.ErrNotFound):
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "not_found"})
	case errors.Is(err, domain.ErrConflict):
		return c.Status(http.StatusConflict).JSON(fiber.Map{
			"error":   "conflict",
			"message": err.Error(),
		})
	case errors.Is(err, domain.ErrForbidden):
		return nil
	default:
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "internal"})
	}
}
