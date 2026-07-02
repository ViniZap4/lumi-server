// Ownership + share-a-copy (v3 Phase O). See SPEC-V3.md "Vault model" and
// "Sharing". Transfer is owner-gated (not capability-gated); copy is gated
// on vault.export by the route middleware.
package vaults

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// ErrRecipientNotFound distinguishes "no such recipient user" from other
// validation failures so the handler can answer precisely.
var ErrRecipientNotFound = fmt.Errorf("%w: recipient not found", domain.ErrValidation)

// MemberDirectory extends the create-time MemberAdder with the lookups the
// transfer flow needs. Implemented by *pg.MemberStore.
type MemberDirectory interface {
	Get(ctx context.Context, vaultID, userID uuid.UUID) (domain.Member, error)
	ChangeRole(ctx context.Context, vaultID, userID, newRoleID uuid.UUID) error
}

// UserDirectory resolves share-a-copy recipients. Implemented by *pg.UserStore.
type UserDirectory interface {
	GetByUsername(ctx context.Context, username string) (domain.User, error)
}

// NoteCopier forks note files + metadata + CRDT state from one vault into
// another. Implemented by *notes.Service.
type NoteCopier interface {
	CopyVaultNotes(ctx context.Context, srcVaultID, dstVaultID, actor uuid.UUID) (int, error)
}

// SetOwnershipDeps wires the transfer + copy collaborators. Called by the
// composition root; the endpoints answer 503-ish internal errors until wired.
func (s *Service) SetOwnershipDeps(members MemberDirectory, users UserDirectory, copier NoteCopier) {
	s.memberDir = members
	s.users = users
	s.copier = copier
}

// TransferOwnership reassigns the vault owner. Only the current owner may
// transfer; the new owner must already be a member and is promoted to the
// seed Admin role so the grant reality matches the owner invariant.
func (s *Service) TransferOwnership(ctx context.Context, vaultID, newOwner, actor uuid.UUID, ip, ua string) (domain.Vault, error) {
	if s.memberDir == nil {
		return domain.Vault{}, errors.New("vaults: ownership deps not wired")
	}
	v, err := s.repo.GetByID(ctx, vaultID)
	if err != nil {
		return domain.Vault{}, err
	}
	if v.OwnerUserID != actor {
		return domain.Vault{}, fmt.Errorf("%w: only the owner can transfer ownership", domain.ErrForbidden)
	}
	if newOwner == v.OwnerUserID {
		return v, nil
	}

	member, err := s.memberDir.Get(ctx, vaultID, newOwner)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.Vault{}, fmt.Errorf("%w: new owner must be a vault member", domain.ErrValidation)
		}
		return domain.Vault{}, err
	}
	adminRole, err := s.roles.GetByName(ctx, vaultID, "Admin")
	if err != nil {
		return domain.Vault{}, fmt.Errorf("lookup admin role: %w", err)
	}
	if member.RoleID != adminRole.ID {
		if err := s.memberDir.ChangeRole(ctx, vaultID, newOwner, adminRole.ID); err != nil {
			return domain.Vault{}, fmt.Errorf("promote new owner: %w", err)
		}
	}
	if err := s.repo.UpdateOwner(ctx, vaultID, newOwner); err != nil {
		return domain.Vault{}, err
	}

	s.recordAudit(ctx, actor, vaultID, domain.ActionVaultTransfer, ip, ua, map[string]any{
		"vault_id":  vaultID,
		"owner_old": v.OwnerUserID,
		"owner_new": newOwner,
	})
	v.OwnerUserID = newOwner
	return v, nil
}

// CopyInput parameterises share-a-copy.
type CopyInput struct {
	RecipientUsername string
	Actor             uuid.UUID
	IP                string
	UserAgent         string
}

// CopyToUser forks the vault's current state into a brand-new vault owned by
// the recipient: fresh id/slug, seed roles, recipient as sole Admin member,
// copied notes + CRDT state, no live link back. Provenance lands in
// copied_from and a vault.copy audit entry on the source vault.
func (s *Service) CopyToUser(ctx context.Context, vaultID uuid.UUID, in CopyInput) (domain.Vault, error) {
	if s.users == nil || s.copier == nil {
		return domain.Vault{}, errors.New("vaults: ownership deps not wired")
	}
	src, err := s.repo.GetByID(ctx, vaultID)
	if err != nil {
		return domain.Vault{}, err
	}
	recipient, err := s.users.GetByUsername(ctx, strings.TrimSpace(in.RecipientUsername))
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.Vault{}, ErrRecipientNotFound
		}
		return domain.Vault{}, err
	}

	dst, err := s.createForCopy(ctx, src, recipient.ID, in)
	if err != nil {
		return domain.Vault{}, err
	}

	provenance, _ := json.Marshal(map[string]any{
		"vault_id":  src.ID,
		"slug":      src.Slug,
		"copied_by": in.Actor,
		"copied_at": s.now().UTC().Format("2006-01-02T15:04:05Z07:00"),
	})
	if err := s.repo.SetCopiedFrom(ctx, dst.ID, provenance); err != nil {
		s.rollbackCopy(ctx, dst)
		return domain.Vault{}, err
	}
	dst.CopiedFrom = provenance

	copied, err := s.copier.CopyVaultNotes(ctx, src.ID, dst.ID, in.Actor)
	if err != nil {
		s.rollbackCopy(ctx, dst)
		return domain.Vault{}, fmt.Errorf("copy notes: %w", err)
	}

	s.recordAudit(ctx, in.Actor, src.ID, domain.ActionVaultCopy, in.IP, in.UserAgent, map[string]any{
		"src_vault_id":      src.ID,
		"dst_vault_id":      dst.ID,
		"recipient_user_id": recipient.ID,
		"notes_copied":      copied,
	})
	return dst, nil
}

// createForCopy runs the standard vault bootstrap for the recipient, retrying
// with slug suggestions on collision (the recipient isn't present to pick).
func (s *Service) createForCopy(ctx context.Context, src domain.Vault, recipientID uuid.UUID, in CopyInput) (domain.Vault, error) {
	name := src.Name + " (copy)"
	slugs := append([]string{""}, SuggestAlternatives(SuggestSlug(name))...)
	var lastErr error
	for _, slug := range slugs {
		dst, err := s.Create(ctx, CreateInput{
			Name:      name,
			Slug:      slug,
			CreatedBy: recipientID,
			IP:        in.IP,
			UserAgent: in.UserAgent,
		})
		if err == nil {
			return dst, nil
		}
		lastErr = err
		var taken *SlugTakenError
		if !errors.As(err, &taken) {
			return domain.Vault{}, err
		}
	}
	return domain.Vault{}, lastErr
}

// rollbackCopy undoes a partially-forked vault. Best-effort: the DB row is
// authoritative, the dir removal mirrors vaults.Service.Delete semantics.
func (s *Service) rollbackCopy(ctx context.Context, dst domain.Vault) {
	_ = s.repo.Delete(ctx, dst.ID)
	_ = s.fs.RemoveVaultDir(dst.Slug)
}

// ---- Handlers ----------------------------------------------------------------

type transferReq struct {
	UserID uuid.UUID `json:"user_id"`
}

func (h *Handlers) transferOwnership(c *fiber.Ctx) error {
	vaultID, err := uuid.Parse(c.Params("vault"))
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_vault_id"})
	}
	u, err := userFromCtx(c)
	if err != nil {
		return mapErr(c, err)
	}
	var req transferReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_body"})
	}
	if req.UserID == uuid.Nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "user_id_required"})
	}
	v, err := h.svc.TransferOwnership(c.UserContext(), vaultID, req.UserID, u.ID, c.IP(), string(c.Request().Header.UserAgent()))
	if err != nil {
		return mapErr(c, err)
	}
	return c.JSON(toDTO(v))
}

type copyReq struct {
	RecipientUsername string `json:"recipient_username"`
}

func (h *Handlers) copy(c *fiber.Ctx) error {
	vaultID, err := uuid.Parse(c.Params("vault"))
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_vault_id"})
	}
	u, err := userFromCtx(c)
	if err != nil {
		return mapErr(c, err)
	}
	var req copyReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_body"})
	}
	if strings.TrimSpace(req.RecipientUsername) == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "recipient_username_required"})
	}
	v, err := h.svc.CopyToUser(c.UserContext(), vaultID, CopyInput{
		RecipientUsername: req.RecipientUsername,
		Actor:             u.ID,
		IP:                c.IP(),
		UserAgent:         string(c.Request().Header.UserAgent()),
	})
	if err != nil {
		if errors.Is(err, ErrRecipientNotFound) {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "recipient_not_found"})
		}
		return mapErr(c, err)
	}
	return c.Status(http.StatusCreated).JSON(toDTO(v))
}
