// Package users implements user-facing CRUD plus the LGPD-mandated data
// export and account-erasure flows. Authentication primitives (login/
// register/logout/me/password) live in internal/auth; this package
// implements only profile management and the data-subject-rights endpoints.
package users

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/ViniZap4/lumi-server/internal/audit"
	"github.com/ViniZap4/lumi-server/internal/domain"
)

const ExportRateLimitWindow = 24 * time.Hour
const MaxDisplayNameLen = 80

// Repo is the storage surface this package needs.
type Repo interface {
	GetByID(ctx context.Context, id uuid.UUID) (domain.User, error)
	GetByUsername(ctx context.Context, username string) (domain.User, error)
	UpdateDisplayName(ctx context.Context, id uuid.UUID, name string) error
	Delete(ctx context.Context, id uuid.UUID, forceDeleteSoleAdminVaults bool) error
	SoleAdminVaultIDs(ctx context.Context, id uuid.UUID) ([]uuid.UUID, error)
}

// ConsentReader exposes the consent ledger for export.
type ConsentReader interface {
	ListForUser(ctx context.Context, userID uuid.UUID) ([]domain.Consent, error)
}

// AuditReader exposes the user's audit history for export + rate-limit lookup.
type AuditReader interface {
	ListForUser(ctx context.Context, userID uuid.UUID, limit, offset int) ([]domain.AuditEntry, error)
	LatestActionAt(ctx context.Context, userID uuid.UUID, action string) (any, error)
}

// VaultLister returns vaults visible to the user for export.
type VaultLister interface {
	ListForUser(ctx context.Context, userID uuid.UUID) ([]domain.Vault, error)
}

// PasswordChecker validates a plaintext password. Implemented by *auth.Service.
type PasswordChecker interface {
	CheckPassword(ctx context.Context, userID uuid.UUID, password string) error
}

// Service orchestrates user CRUD plus the two LGPD endpoints.
type Service struct {
	repo     Repo
	consents ConsentReader
	audit    AuditReader
	recorder audit.Recorder
	vaults   VaultLister
	now      func() time.Time
}

func NewService(repo Repo, consents ConsentReader, auditR AuditReader, recorder audit.Recorder, vaults VaultLister) *Service {
	if repo == nil || consents == nil || auditR == nil || recorder == nil || vaults == nil {
		panic("users.NewService: all dependencies are required")
	}
	return &Service{
		repo:     repo,
		consents: consents,
		audit:    auditR,
		recorder: recorder,
		vaults:   vaults,
		now:      time.Now,
	}
}

func (s *Service) Get(ctx context.Context, id uuid.UUID) (domain.User, error) {
	return s.repo.GetByID(ctx, id)
}

// UpdateDisplayName trims, length-checks, and writes.
func (s *Service) UpdateDisplayName(ctx context.Context, id uuid.UUID, name string, ip, ua *string) error {
	name = strings.TrimSpace(name)
	if n := utf8.RuneCountInString(name); n < 1 || n > MaxDisplayNameLen {
		return fmt.Errorf("display_name length %d out of range [1,%d]: %w", n, MaxDisplayNameLen, domain.ErrValidation)
	}
	if err := s.repo.UpdateDisplayName(ctx, id, name); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{"field": "display_name"})
	_ = s.recorder.Record(ctx, domain.AuditEntry{
		UserID:    &id,
		Action:    domain.ActionUserUpdate,
		Payload:   payload,
		IP:        ip,
		UserAgent: ua,
		CreatedAt: s.now(),
	})
	return nil
}

// SoleAdminError carries the offending vault ids when the caller hasn't
// opted into deleting them.
type SoleAdminError struct{ VaultIDs []uuid.UUID }

func (e SoleAdminError) Error() string {
	return fmt.Sprintf("sole admin of %d vault(s)", len(e.VaultIDs))
}
func (e SoleAdminError) Unwrap() error { return domain.ErrSoleAdminVaults }

// Delete enacts LGPD right of erasure.
func (s *Service) Delete(ctx context.Context, id uuid.UUID, forceVaults bool, ip, ua *string) error {
	soleAdmin, err := s.repo.SoleAdminVaultIDs(ctx, id)
	if err != nil {
		return fmt.Errorf("sole-admin check: %w", err)
	}
	if len(soleAdmin) > 0 && !forceVaults {
		return SoleAdminError{VaultIDs: soleAdmin}
	}

	payload, _ := json.Marshal(map[string]any{
		"force_delete_sole_admin_vaults": forceVaults,
		"sole_admin_vault_ids":           soleAdmin,
	})
	if err := s.recorder.Record(ctx, domain.AuditEntry{
		UserID:    &id,
		Action:    domain.ActionUserDelete,
		Payload:   payload,
		IP:        ip,
		UserAgent: ua,
		CreatedAt: s.now(),
	}); err != nil {
		return fmt.Errorf("audit user.delete: %w", err)
	}

	return s.repo.Delete(ctx, id, forceVaults)
}

// CanExportNow returns false if the most recent user.export_request audit
// entry for this user is within ExportRateLimitWindow.
func (s *Service) CanExportNow(ctx context.Context, id uuid.UUID) (bool, error) {
	last, err := s.audit.LatestActionAt(ctx, id, domain.ActionUserExportRequest)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return true, nil
		}
		return false, err
	}
	t, ok := last.(time.Time)
	if !ok {
		return true, nil
	}
	return s.now().Sub(t) >= ExportRateLimitWindow, nil
}

// Manifest is the top-level export descriptor.
type Manifest struct {
	GeneratedAt time.Time           `json:"generated_at"`
	Version     string              `json:"manifest_version"`
	User        ManifestUser        `json:"user"`
	Vaults      []ManifestVault     `json:"vaults"`
	Audit       []domain.AuditEntry `json:"audit"`
	Consents    []domain.Consent    `json:"consents"`
}

type ManifestUser struct {
	ID          uuid.UUID `json:"id"`
	Username    string    `json:"username"`
	DisplayName string    `json:"display_name"`
	CreatedAt   time.Time `json:"created_at"`
}

type ManifestVault struct {
	ID   uuid.UUID `json:"id"`
	Slug string    `json:"slug"`
	Name string    `json:"name"`
}

// Export builds a zip in memory and returns it. Phase 1 keeps it simple
// (manifest + consents + audit + vault metadata; not note bodies). Phase 2
// extends to streaming + per-vault note content.
func (s *Service) Export(ctx context.Context, id uuid.UUID) ([]byte, error) {
	user, err := s.repo.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	consents, err := s.consents.ListForUser(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("consents: %w", err)
	}
	auditEntries, err := s.audit.ListForUser(ctx, id, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("audit list: %w", err)
	}
	vaultList, err := s.vaults.ListForUser(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("vaults: %w", err)
	}

	mvs := make([]ManifestVault, 0, len(vaultList))
	for _, v := range vaultList {
		mvs = append(mvs, ManifestVault{ID: v.ID, Slug: v.Slug, Name: v.Name})
	}

	manifest := Manifest{
		GeneratedAt: s.now().UTC(),
		Version:     "1.0",
		User: ManifestUser{
			ID:          user.ID,
			Username:    user.Username,
			DisplayName: user.DisplayName,
			CreatedAt:   user.CreatedAt,
		},
		Vaults:   mvs,
		Audit:    auditEntries,
		Consents: consents,
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if err := writeJSON(zw, "manifest.json", manifest); err != nil {
		return nil, err
	}
	if err := writeJSON(zw, "consents.json", consents); err != nil {
		return nil, err
	}
	if err := writeJSON(zw, "audit.json", auditEntries); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("zip close: %w", err)
	}
	return buf.Bytes(), nil
}

// RecordExportRequest stamps the rate-limit window start.
func (s *Service) RecordExportRequest(ctx context.Context, id uuid.UUID, ip, ua *string) error {
	return s.recorder.Record(ctx, domain.AuditEntry{
		UserID:    &id,
		Action:    domain.ActionUserExportRequest,
		IP:        ip,
		UserAgent: ua,
		CreatedAt: s.now(),
	})
}

func writeJSON(zw *zip.Writer, name string, v any) error {
	w, err := zw.Create(name)
	if err != nil {
		return fmt.Errorf("create %s: %w", name, err)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("encode %s: %w", name, err)
	}
	return nil
}

// ---- Handlers ---------------------------------------------------------

const userIDKey = "auth.user"

type Handlers struct {
	svc      *Service
	password PasswordChecker
}

func NewHandlers(svc *Service, pc PasswordChecker) *Handlers {
	if svc == nil || pc == nil {
		panic("users.NewHandlers: svc and password checker required")
	}
	return &Handlers{svc: svc, password: pc}
}

func (h *Handlers) Register(r fiber.Router) {
	r.Get("/users/me/export", h.Export)
	r.Delete("/users/me", h.DeleteMe)
}

func (h *Handlers) currentUser(c *fiber.Ctx) (uuid.UUID, error) {
	v := c.Locals(userIDKey)
	if v == nil {
		return uuid.Nil, domain.ErrUnauthorized
	}
	u, ok := v.(*domain.User)
	if !ok || u == nil {
		return uuid.Nil, domain.ErrUnauthorized
	}
	return u.ID, nil
}

func (h *Handlers) Export(c *fiber.Ctx) error {
	uid, err := h.currentUser(c)
	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	ctx := c.UserContext()

	ok, err := h.svc.CanExportNow(ctx, uid)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "internal"})
	}
	if !ok {
		c.Set("Retry-After", fmt.Sprintf("%d", int(ExportRateLimitWindow.Seconds())))
		return c.Status(http.StatusTooManyRequests).JSON(fiber.Map{
			"error":         "rate_limited",
			"retry_after_s": int(ExportRateLimitWindow.Seconds()),
		})
	}

	ip, ua := callerIP(c), callerUA(c)
	if err := h.svc.RecordExportRequest(ctx, uid, ip, ua); err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "audit_unavailable"})
	}

	user, err := h.svc.Get(ctx, uid)
	if err != nil {
		return mapErr(c, err)
	}

	body, err := h.svc.Export(ctx, uid)
	if err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "export_failed"})
	}

	filename := fmt.Sprintf("lumi-export-%s-%s.zip",
		safeFilename(user.Username),
		time.Now().UTC().Format("2006-01-02"),
	)
	c.Set(fiber.HeaderContentType, "application/zip")
	c.Set(fiber.HeaderContentDisposition, fmt.Sprintf(`attachment; filename=%q`, filename))
	c.Set(fiber.HeaderCacheControl, "no-store")
	return c.Send(body)
}

type deleteMeReq struct {
	Password              string `json:"password"`
	DeleteSoleAdminVaults bool   `json:"delete_sole_admin_vaults"`
}

func (h *Handlers) DeleteMe(c *fiber.Ctx) error {
	uid, err := h.currentUser(c)
	if err != nil {
		return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "unauthorized"})
	}
	ctx := c.UserContext()

	var body deleteMeReq
	if err := c.BodyParser(&body); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid_body"})
	}
	if body.Password == "" {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "password_required"})
	}
	if err := h.password.CheckPassword(ctx, uid, body.Password); err != nil {
		if errors.Is(err, domain.ErrInvalidCredentials) {
			return c.Status(http.StatusUnauthorized).JSON(fiber.Map{"error": "invalid_credentials"})
		}
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "internal"})
	}

	ip, ua := callerIP(c), callerUA(c)
	if err := h.svc.Delete(ctx, uid, body.DeleteSoleAdminVaults, ip, ua); err != nil {
		var soleAdmin SoleAdminError
		if errors.As(err, &soleAdmin) {
			return c.Status(http.StatusConflict).JSON(fiber.Map{
				"error":     "sole_admin_vaults",
				"vault_ids": soleAdmin.VaultIDs,
			})
		}
		return mapErr(c, err)
	}
	return c.SendStatus(http.StatusNoContent)
}

func callerIP(c *fiber.Ctx) *string {
	ip := c.IP()
	if ip == "" {
		return nil
	}
	return &ip
}

func callerUA(c *fiber.Ctx) *string {
	ua := c.Get(fiber.HeaderUserAgent)
	if ua == "" {
		return nil
	}
	return &ua
}

func safeFilename(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z',
			r >= 'a' && r <= 'z',
			r >= '0' && r <= '9',
			r == '_' || r == '-' || r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "user"
	}
	return b.String()
}

func mapErr(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return c.Status(http.StatusNotFound).JSON(fiber.Map{"error": "not_found"})
	case errors.Is(err, domain.ErrValidation):
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "validation"})
	case errors.Is(err, domain.ErrConflict):
		return c.Status(http.StatusConflict).JSON(fiber.Map{"error": "conflict"})
	default:
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "internal"})
	}
}
