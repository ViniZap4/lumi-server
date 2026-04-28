// Package members owns vault membership: who is in a vault, what role they
// hold, and the rules for adding/removing them.
package members

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/audit"
	"github.com/ViniZap4/lumi-server/internal/capguard"
	"github.com/ViniZap4/lumi-server/internal/domain"
)

// MemberJoined is the JOIN-resolved view used by ListForVault.
type MemberJoined struct {
	Member domain.Member
	User   domain.User
	Role   domain.Role
}

// Repo is the persistence boundary for vault_members.
type Repo interface {
	Add(ctx context.Context, m domain.Member) error
	Remove(ctx context.Context, vaultID, userID uuid.UUID) error
	ChangeRole(ctx context.Context, vaultID, userID, newRoleID uuid.UUID) error
	Get(ctx context.Context, vaultID, userID uuid.UUID) (domain.Member, error)
	ListForVault(ctx context.Context, vaultID uuid.UUID) ([]MemberJoined, error)
	IsSoleAdmin(ctx context.Context, vaultID, userID uuid.UUID) (bool, error)
	RoleForUser(ctx context.Context, vaultID, userID uuid.UUID) (domain.Role, error)
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

// RoleForUser implements capguard.Resolver.
func (s *Service) RoleForUser(ctx context.Context, vaultID, userID uuid.UUID) (domain.Role, error) {
	return s.repo.RoleForUser(ctx, vaultID, userID)
}

func (s *Service) List(ctx context.Context, vaultID uuid.UUID) ([]MemberJoined, error) {
	return s.repo.ListForVault(ctx, vaultID)
}

// Add is used by the invite-accept flow.
func (s *Service) Add(ctx context.Context, m domain.Member, ip, ua string) error {
	if err := s.repo.Add(ctx, m); err != nil {
		return err
	}
	s.recordAudit(ctx, domain.ActionMemberAdd, m.UserID, m.VaultID, ip, ua, map[string]any{
		"member_user_id": m.UserID.String(),
		"role_id":        m.RoleID.String(),
	})
	return nil
}

// ChangeRole refuses to demote the sole admin.
func (s *Service) ChangeRole(
	ctx context.Context,
	vaultID, userID, newRoleID uuid.UUID,
	actorID uuid.UUID,
	ip, ua string,
) error {
	current, err := s.repo.Get(ctx, vaultID, userID)
	if err != nil {
		return err
	}
	if current.RoleID == newRoleID {
		return nil
	}
	sole, err := s.repo.IsSoleAdmin(ctx, vaultID, userID)
	if err != nil {
		return err
	}
	if sole {
		// Verify the new role is also Admin (lookup via role list join).
		joined, err := s.repo.ListForVault(ctx, vaultID)
		if err != nil {
			return err
		}
		var newRole *domain.Role
		for i := range joined {
			if joined[i].Role.ID == newRoleID {
				newRole = &joined[i].Role
				break
			}
		}
		if newRole == nil || !(newRole.IsSeed && newRole.Name == "Admin") {
			return ErrSoleAdminProtection{VaultID: vaultID, UserID: userID}
		}
	}

	if err := s.repo.ChangeRole(ctx, vaultID, userID, newRoleID); err != nil {
		return err
	}
	s.recordAudit(ctx, domain.ActionMemberRoleChange, actorID, vaultID, ip, ua, map[string]any{
		"member_user_id": userID.String(),
		"role_id_old":    current.RoleID.String(),
		"role_id_new":    newRoleID.String(),
	})
	return nil
}

// Remove refuses to remove the sole admin.
func (s *Service) Remove(
	ctx context.Context,
	vaultID, userID uuid.UUID,
	actorID uuid.UUID,
	ip, ua string,
) error {
	if _, err := s.repo.Get(ctx, vaultID, userID); err != nil {
		return err
	}
	sole, err := s.repo.IsSoleAdmin(ctx, vaultID, userID)
	if err != nil {
		return err
	}
	if sole {
		return ErrSoleAdminProtection{VaultID: vaultID, UserID: userID}
	}
	if err := s.repo.Remove(ctx, vaultID, userID); err != nil {
		return err
	}
	s.recordAudit(ctx, domain.ActionMemberRemove, actorID, vaultID, ip, ua, map[string]any{
		"member_user_id": userID.String(),
	})
	return nil
}

type ErrSoleAdminProtection struct {
	VaultID uuid.UUID
	UserID  uuid.UUID
}

func (e ErrSoleAdminProtection) Error() string {
	return fmt.Sprintf("user %s is the sole admin of vault %s; promote another admin first", e.UserID, e.VaultID)
}

func (e ErrSoleAdminProtection) Unwrap() error { return domain.ErrConflict }

func IsSoleAdminProtection(err error) bool {
	var t ErrSoleAdminProtection
	return errors.As(err, &t)
}

func (s *Service) recordAudit(ctx context.Context, action string, userID, vaultID uuid.UUID, ip, ua string, payload map[string]any) {
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{}`)
	}
	entry := domain.AuditEntry{Action: action, Payload: body}
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

// ---- Handlers --------------------------------------------------------------

type Handlers struct {
	svc      *Service
	resolver capguard.Resolver
}

func NewHandlers(svc *Service, resolver capguard.Resolver) *Handlers {
	return &Handlers{svc: svc, resolver: resolver}
}

func (h *Handlers) Register(r fiber.Router) {
	r.Get("/vaults/:vault/members", h.list)
	r.Patch("/vaults/:vault/members/:user",
		capguard.RequireCapability(h.resolver, domain.CapMembersManage),
		h.changeRole,
	)
	r.Delete("/vaults/:vault/members/:user",
		capguard.RequireCapability(h.resolver, domain.CapMembersManage),
		h.remove,
	)
}

type memberDTO struct {
	VaultID      uuid.UUID            `json:"vault_id"`
	UserID       uuid.UUID            `json:"user_id"`
	Username     string               `json:"username"`
	DisplayName  string               `json:"display_name"`
	RoleID       uuid.UUID            `json:"role_id"`
	RoleName     string               `json:"role_name"`
	Capabilities domain.CapabilitySet `json:"capabilities"`
	IsSeedRole   bool                 `json:"is_seed_role"`
	JoinedAt     string               `json:"joined_at"`
}

func toMemberDTO(m MemberJoined) memberDTO {
	caps := m.Role.Capabilities
	if caps == nil {
		caps = domain.CapabilitySet{}
	}
	return memberDTO{
		VaultID:      m.Member.VaultID,
		UserID:       m.Member.UserID,
		Username:     m.User.Username,
		DisplayName:  m.User.DisplayName,
		RoleID:       m.Role.ID,
		RoleName:     m.Role.Name,
		Capabilities: caps,
		IsSeedRole:   m.Role.IsSeed,
		JoinedAt:     m.Member.JoinedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
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
	rows, err := h.svc.List(c.UserContext(), vid)
	if err != nil {
		return mapError(c, err)
	}
	out := make([]memberDTO, 0, len(rows))
	for _, r := range rows {
		out = append(out, toMemberDTO(r))
	}
	return c.Status(http.StatusOK).JSON(fiber.Map{"members": out})
}

type changeRoleReq struct {
	RoleID uuid.UUID `json:"role_id"`
}

func (h *Handlers) changeRole(c *fiber.Ctx) error {
	vid, err := capguard.WithVaultID(c)
	if err != nil {
		return nil
	}
	uid, err := capguard.WithUserID(c)
	if err != nil {
		return nil
	}
	var req changeRoleReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_body"})
	}
	if req.RoleID == uuid.Nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "role_id_required"})
	}
	actor, _ := capguard.UserIDFrom(c)
	if err := h.svc.ChangeRole(c.UserContext(), vid, uid, req.RoleID, actor, c.IP(), string(c.Request().Header.UserAgent())); err != nil {
		return mapError(c, err)
	}
	return c.SendStatus(http.StatusNoContent)
}

func (h *Handlers) remove(c *fiber.Ctx) error {
	vid, err := capguard.WithVaultID(c)
	if err != nil {
		return nil
	}
	uid, err := capguard.WithUserID(c)
	if err != nil {
		return nil
	}
	actor, _ := capguard.UserIDFrom(c)
	if err := h.svc.Remove(c.UserContext(), vid, uid, actor, c.IP(), string(c.Request().Header.UserAgent())); err != nil {
		return mapError(c, err)
	}
	return c.SendStatus(http.StatusNoContent)
}

func mapError(c *fiber.Ctx, err error) error {
	switch {
	case IsSoleAdminProtection(err):
		return c.Status(http.StatusConflict).JSON(fiber.Map{
			"error":   "sole_admin",
			"message": err.Error(),
		})
	case errors.Is(err, domain.ErrNotFound):
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "not_found"})
	case errors.Is(err, domain.ErrValidation):
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error":   "validation_failed",
			"message": err.Error(),
		})
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
