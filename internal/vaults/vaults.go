// Package vaults owns vault lifecycle: CRUD on the vaults row, slug
// allocation, seeding of the four built-in roles, the creator-as-Admin
// membership bootstrap, and the on-disk <root>/<slug>/.lumi/vault.yaml
// provisioning.
package vaults

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/audit"
	"github.com/ViniZap4/lumi-server/internal/capguard"
	"github.com/ViniZap4/lumi-server/internal/domain"
	"github.com/ViniZap4/lumi-server/internal/storage/fs"
)

// VaultRepo persists vault rows.
type VaultRepo interface {
	Create(ctx context.Context, v domain.Vault) (domain.Vault, error)
	GetByID(ctx context.Context, id uuid.UUID) (domain.Vault, error)
	GetBySlug(ctx context.Context, slug string) (domain.Vault, error)
	ListForUser(ctx context.Context, userID uuid.UUID) ([]domain.Vault, error)
	UpdateName(ctx context.Context, id uuid.UUID, name string) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// RoleSeeder seeds the canonical roles for a new vault.
type RoleSeeder interface {
	SeedForVault(ctx context.Context, vaultID uuid.UUID) ([]domain.Role, error)
	GetByName(ctx context.Context, vaultID uuid.UUID, name string) (domain.Role, error)
}

// MemberAdder adds the creator as Admin.
type MemberAdder interface {
	Add(ctx context.Context, m domain.Member) error
}

// Service orchestrates vault lifecycle.
type Service struct {
	repo     VaultRepo
	roles    RoleSeeder
	members  MemberAdder
	fs       *fs.Manager
	audit    audit.Recorder
	resolver capguard.Resolver
	now      func() time.Time
}

func NewService(
	repo VaultRepo,
	roles RoleSeeder,
	members MemberAdder,
	fsMgr *fs.Manager,
	a audit.Recorder,
	resolver capguard.Resolver,
) *Service {
	if repo == nil || roles == nil || members == nil || fsMgr == nil || resolver == nil {
		panic("vaults.NewService: missing dependency")
	}
	if a == nil {
		a = audit.Noop{}
	}
	return &Service{
		repo:     repo,
		roles:    roles,
		members:  members,
		fs:       fsMgr,
		audit:    a,
		resolver: resolver,
		now:      time.Now,
	}
}

// ---- Slug ------------------------------------------------------------------

var slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

const maxSlugLen = 63

func ValidateSlug(s string) error {
	if s == "" {
		return fmt.Errorf("%w: slug is required", domain.ErrValidation)
	}
	if len(s) > maxSlugLen {
		return fmt.Errorf("%w: slug exceeds %d characters", domain.ErrValidation, maxSlugLen)
	}
	if !slugRE.MatchString(s) {
		return fmt.Errorf("%w: slug must match %s", domain.ErrValidation, slugRE.String())
	}
	if s == "." || s == ".." || strings.Contains(s, "/") || strings.Contains(s, "\\") {
		return fmt.Errorf("%w: slug must not contain path separators", domain.ErrValidation)
	}
	return nil
}

// SuggestSlug normalises an arbitrary string into a candidate slug.
func SuggestSlug(base string) string {
	lowered := strings.ToLower(strings.TrimSpace(base))
	var b strings.Builder
	b.Grow(len(lowered))
	prevHyphen := true
	for _, r := range lowered {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevHyphen = false
		default:
			folded := foldRune(r)
			if folded != 0 {
				b.WriteRune(folded)
				prevHyphen = false
				continue
			}
			if !prevHyphen {
				b.WriteByte('-')
				prevHyphen = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > maxSlugLen {
		out = strings.TrimRight(out[:maxSlugLen], "-")
	}
	if out == "" {
		return "vault"
	}
	return out
}

func foldRune(r rune) rune {
	switch r {
	case 'á', 'à', 'â', 'ã', 'ä', 'å':
		return 'a'
	case 'ç':
		return 'c'
	case 'é', 'è', 'ê', 'ë':
		return 'e'
	case 'í', 'ì', 'î', 'ï':
		return 'i'
	case 'ñ':
		return 'n'
	case 'ó', 'ò', 'ô', 'õ', 'ö':
		return 'o'
	case 'ú', 'ù', 'û', 'ü':
		return 'u'
	case 'ý', 'ÿ':
		return 'y'
	}
	return 0
}

func SuggestAlternatives(base string) []string {
	root := SuggestSlug(base)
	out := make([]string, 0, 5)
	for i := 2; i <= 6; i++ {
		suffix := fmt.Sprintf("-%d", i)
		head := root
		if len(head)+len(suffix) > maxSlugLen {
			head = strings.TrimRight(head[:maxSlugLen-len(suffix)], "-")
			if head == "" {
				head = "vault"
			}
		}
		out = append(out, head+suffix)
	}
	return out
}

// ---- Service methods -------------------------------------------------------

type CreateInput struct {
	Name      string
	Slug      string
	CreatedBy uuid.UUID
	IP        string
	UserAgent string
}

// SlugTakenError is returned when the requested slug collides.
type SlugTakenError struct {
	Slug        string
	Suggestions []string
}

func (e *SlugTakenError) Error() string { return fmt.Sprintf("slug %q taken", e.Slug) }
func (e *SlugTakenError) Unwrap() error { return domain.ErrConflict }

// Create runs the vault bootstrap: validate slug, insert vault, seed roles,
// add creator as Admin, provision the FS dir, audit-log.
//
// Phase 1 trade-off: not transactional (the storage layer doesn't expose a
// cross-table tx yet). On partial failure the service rolls back via
// VaultRepo.Delete which cascades the FK chain. Documented in SPEC.md as
// acceptable for v2.0; tightened in Phase 2.
func (s *Service) Create(ctx context.Context, in CreateInput) (domain.Vault, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return domain.Vault{}, fmt.Errorf("%w: name is required", domain.ErrValidation)
	}
	slug := strings.TrimSpace(in.Slug)
	if slug == "" {
		slug = SuggestSlug(name)
	}
	if err := ValidateSlug(slug); err != nil {
		return domain.Vault{}, err
	}

	row := domain.Vault{
		ID:        uuid.New(),
		Slug:      slug,
		Name:      name,
		CreatedBy: in.CreatedBy,
		CreatedAt: s.now().UTC(),
	}
	created, err := s.repo.Create(ctx, row)
	if err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return domain.Vault{}, &SlugTakenError{Slug: slug, Suggestions: SuggestAlternatives(slug)}
		}
		return domain.Vault{}, err
	}

	if _, err := s.roles.SeedForVault(ctx, created.ID); err != nil {
		_ = s.repo.Delete(ctx, created.ID)
		return domain.Vault{}, fmt.Errorf("seed roles: %w", err)
	}
	adminRole, err := s.roles.GetByName(ctx, created.ID, "Admin")
	if err != nil {
		_ = s.repo.Delete(ctx, created.ID)
		return domain.Vault{}, fmt.Errorf("lookup admin role: %w", err)
	}
	if err := s.members.Add(ctx, domain.Member{
		VaultID:  created.ID,
		UserID:   in.CreatedBy,
		RoleID:   adminRole.ID,
		JoinedAt: s.now().UTC(),
	}); err != nil {
		_ = s.repo.Delete(ctx, created.ID)
		return domain.Vault{}, fmt.Errorf("add creator as admin: %w", err)
	}

	if _, err := s.fs.EnsureVaultDir(created.Slug); err != nil {
		_ = s.repo.Delete(ctx, created.ID)
		return domain.Vault{}, fmt.Errorf("provision vault dir: %w", err)
	}
	if err := s.fs.WriteVaultYAML(created.Slug, fs.VaultMetadata{
		ID:        created.ID,
		Name:      created.Name,
		Slug:      created.Slug,
		CreatedAt: created.CreatedAt,
	}); err != nil {
		// Non-fatal: dir is provisioned, vault is valid in DB. Log via audit.
	}

	s.recordAudit(ctx, in.CreatedBy, created.ID, domain.ActionVaultCreate, in.IP, in.UserAgent, map[string]any{
		"vault_id": created.ID,
		"slug":     created.Slug,
		"name":     created.Name,
	})
	return created, nil
}

func (s *Service) Delete(ctx context.Context, vaultID, actor uuid.UUID, ip, ua string) error {
	v, err := s.repo.GetByID(ctx, vaultID)
	if err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, vaultID); err != nil {
		return err
	}
	_ = s.fs.RemoveVaultDir(v.Slug)
	s.recordAudit(ctx, actor, v.ID, domain.ActionVaultDelete, ip, ua, map[string]any{
		"vault_id": v.ID,
		"slug":     v.Slug,
	})
	return nil
}

func (s *Service) UpdateName(ctx context.Context, vaultID uuid.UUID, newName string, actor uuid.UUID, ip, ua string) error {
	name := strings.TrimSpace(newName)
	if name == "" {
		return fmt.Errorf("%w: name is required", domain.ErrValidation)
	}
	if err := s.repo.UpdateName(ctx, vaultID, name); err != nil {
		return err
	}
	s.recordAudit(ctx, actor, vaultID, domain.ActionVaultUpdate, ip, ua, map[string]any{
		"vault_id": vaultID,
		"name":     name,
	})
	return nil
}

func (s *Service) Get(ctx context.Context, vaultID uuid.UUID) (domain.Vault, error) {
	return s.repo.GetByID(ctx, vaultID)
}

func (s *Service) ListForUser(ctx context.Context, userID uuid.UUID) ([]domain.Vault, error) {
	return s.repo.ListForUser(ctx, userID)
}

func (s *Service) recordAudit(ctx context.Context, userID, vaultID uuid.UUID, action, ip, ua string, payload map[string]any) {
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

const userIDKey = "auth.user"

type Handlers struct {
	svc *Service
}

func NewHandlers(svc *Service) *Handlers {
	return &Handlers{svc: svc}
}

func (h *Handlers) Register(r fiber.Router) {
	r.Get("/vaults", h.list)
	r.Post("/vaults", h.create)
	r.Get("/vaults/:vault", h.detail)
	r.Patch("/vaults/:vault",
		capguard.RequireCapability(h.svc.resolver, domain.CapVaultManage),
		h.update,
	)
	r.Delete("/vaults/:vault",
		capguard.RequireCapability(h.svc.resolver, domain.CapVaultManage),
		h.delete,
	)
}

type vaultDTO struct {
	ID        uuid.UUID `json:"id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	CreatedBy uuid.UUID `json:"created_by"`
	CreatedAt string    `json:"created_at"`
}

func toDTO(v domain.Vault) vaultDTO {
	return vaultDTO{
		ID:        v.ID,
		Slug:      v.Slug,
		Name:      v.Name,
		CreatedBy: v.CreatedBy,
		CreatedAt: v.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
	}
}

func userFromCtx(c *fiber.Ctx) (*domain.User, error) {
	v := c.Locals(userIDKey)
	if v == nil {
		return nil, domain.ErrUnauthorized
	}
	u, ok := v.(*domain.User)
	if !ok || u == nil {
		return nil, domain.ErrUnauthorized
	}
	return u, nil
}

func (h *Handlers) list(c *fiber.Ctx) error {
	u, err := userFromCtx(c)
	if err != nil {
		return mapErr(c, err)
	}
	vs, err := h.svc.ListForUser(c.UserContext(), u.ID)
	if err != nil {
		return mapErr(c, err)
	}
	out := make([]vaultDTO, 0, len(vs))
	for _, v := range vs {
		out = append(out, toDTO(v))
	}
	return c.JSON(fiber.Map{"vaults": out})
}

type createReq struct {
	Name string `json:"name"`
	Slug string `json:"slug,omitempty"`
}

func (h *Handlers) create(c *fiber.Ctx) error {
	u, err := userFromCtx(c)
	if err != nil {
		return mapErr(c, err)
	}
	var req createReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_body"})
	}
	v, err := h.svc.Create(c.UserContext(), CreateInput{
		Name:      req.Name,
		Slug:      req.Slug,
		CreatedBy: u.ID,
		IP:        c.IP(),
		UserAgent: string(c.Request().Header.UserAgent()),
	})
	if err != nil {
		var taken *SlugTakenError
		if errors.As(err, &taken) {
			return c.Status(http.StatusConflict).JSON(fiber.Map{
				"error":       "slug_taken",
				"slug":        taken.Slug,
				"suggestions": taken.Suggestions,
			})
		}
		return mapErr(c, err)
	}
	return c.Status(http.StatusCreated).JSON(toDTO(v))
}

func (h *Handlers) detail(c *fiber.Ctx) error {
	u, err := userFromCtx(c)
	if err != nil {
		return mapErr(c, err)
	}
	vaultID, err := uuid.Parse(c.Params("vault"))
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_vault_id"})
	}
	if _, err := h.svc.resolver.RoleForUser(c.UserContext(), vaultID, u.ID); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "not_found"})
		}
		return mapErr(c, err)
	}
	v, err := h.svc.Get(c.UserContext(), vaultID)
	if err != nil {
		return mapErr(c, err)
	}
	return c.JSON(toDTO(v))
}

type updateReq struct {
	Name string `json:"name"`
}

func (h *Handlers) update(c *fiber.Ctx) error {
	vaultID, err := uuid.Parse(c.Params("vault"))
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_vault_id"})
	}
	u, err := userFromCtx(c)
	if err != nil {
		return mapErr(c, err)
	}
	var req updateReq
	if err := c.BodyParser(&req); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_body"})
	}
	if err := h.svc.UpdateName(c.UserContext(), vaultID, req.Name, u.ID, c.IP(), string(c.Request().Header.UserAgent())); err != nil {
		return mapErr(c, err)
	}
	v, err := h.svc.Get(c.UserContext(), vaultID)
	if err != nil {
		return mapErr(c, err)
	}
	return c.JSON(toDTO(v))
}

func (h *Handlers) delete(c *fiber.Ctx) error {
	vaultID, err := uuid.Parse(c.Params("vault"))
	if err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_vault_id"})
	}
	u, err := userFromCtx(c)
	if err != nil {
		return mapErr(c, err)
	}
	if err := h.svc.Delete(c.UserContext(), vaultID, u.ID, c.IP(), string(c.Request().Header.UserAgent())); err != nil {
		return mapErr(c, err)
	}
	return c.SendStatus(http.StatusNoContent)
}

func mapErr(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "not_found"})
	case errors.Is(err, domain.ErrValidation):
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "validation"})
	case errors.Is(err, domain.ErrConflict):
		return c.Status(http.StatusConflict).JSON(fiber.Map{"error": "conflict"})
	case errors.Is(err, domain.ErrUnauthorized):
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	case errors.Is(err, domain.ErrForbidden), errors.Is(err, domain.ErrCapabilityMissing):
		return c.Status(http.StatusForbidden).JSON(fiber.Map{"error": "forbidden"})
	default:
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "internal"})
	}
}
