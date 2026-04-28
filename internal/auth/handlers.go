package auth

import (
	"errors"

	"github.com/gofiber/fiber/v2"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

type Handlers struct {
	svc *Service
}

func NewHandlers(svc *Service) *Handlers {
	if svc == nil {
		panic("auth: NewHandlers called with nil Service")
	}
	return &Handlers{svc: svc}
}

// Register attaches the routes documented in SPEC.md "API surface".
func (h *Handlers) Register(app *fiber.App) {
	app.Post("/api/auth/register", h.RegisterHandler)
	app.Post("/api/auth/login", h.Login)
	app.Post("/api/auth/logout", Required(h.svc), h.Logout)

	app.Get("/api/users/me", Required(h.svc), h.Me)
	app.Patch("/api/users/me", Required(h.svc), h.UpdateMe)
	app.Post("/api/users/me/password", Required(h.svc), h.ChangePassword)
}

type registerReq struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
	Consent     struct {
		TosVersion     string `json:"tos_version"`
		PrivacyVersion string `json:"privacy_version"`
	} `json:"consent"`
}

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type updateMeReq struct {
	DisplayName string `json:"display_name"`
}

type changePasswordReq struct {
	OldPassword string `json:"old_password"`
	NewPassword string `json:"new_password"`
}

type sessionResp struct {
	Token     string  `json:"token"`
	ExpiresAt string  `json:"expires_at"`
	User      userDTO `json:"user"`
}

type userDTO struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
}

func (h *Handlers) RegisterHandler(c *fiber.Ctx) error {
	if h.svc.cfg.RegistrationPolicy != PolicyOpen {
		return errorJSON(c, fiber.StatusForbidden, "registration_closed",
			"public registration is disabled; use an invite link")
	}
	var body registerReq
	if err := c.BodyParser(&body); err != nil {
		return errorJSON(c, fiber.StatusBadRequest, "validation_failed", "invalid json body")
	}
	sess, err := h.svc.Register(c.UserContext(), RegisterInput{
		Username:    body.Username,
		Password:    body.Password,
		DisplayName: body.DisplayName,
		Consent: ConsentInput{
			TosVersion:     body.Consent.TosVersion,
			PrivacyVersion: body.Consent.PrivacyVersion,
		},
		IP:        c.IP(),
		UserAgent: c.Get(fiber.HeaderUserAgent),
	})
	if err != nil {
		return mapServiceErr(c, err)
	}
	user, err := h.svc.users.GetByID(c.UserContext(), sess.UserID)
	if err != nil {
		return c.Status(fiber.StatusCreated).JSON(sessionResp{
			Token:     sess.Token,
			ExpiresAt: sess.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
			User:      userDTO{ID: sess.UserID.String()},
		})
	}
	return c.Status(fiber.StatusCreated).JSON(sessionResp{
		Token:     sess.Token,
		ExpiresAt: sess.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		User: userDTO{
			ID:          user.ID.String(),
			Username:    user.Username,
			DisplayName: user.DisplayName,
		},
	})
}

func (h *Handlers) Login(c *fiber.Ctx) error {
	var body loginReq
	if err := c.BodyParser(&body); err != nil {
		return errorJSON(c, fiber.StatusBadRequest, "validation_failed", "invalid json body")
	}
	sess, err := h.svc.Login(c.UserContext(), LoginInput{
		Username:  body.Username,
		Password:  body.Password,
		IP:        c.IP(),
		UserAgent: c.Get(fiber.HeaderUserAgent),
	})
	if err != nil {
		return mapServiceErr(c, err)
	}
	user, err := h.svc.users.GetByID(c.UserContext(), sess.UserID)
	if err != nil {
		return mapServiceErr(c, err)
	}
	return c.Status(fiber.StatusOK).JSON(sessionResp{
		Token:     sess.Token,
		ExpiresAt: sess.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		User: userDTO{
			ID:          user.ID.String(),
			Username:    user.Username,
			DisplayName: user.DisplayName,
		},
	})
}

func (h *Handlers) Logout(c *fiber.Ctx) error {
	sess := SessionFromCtx(c)
	if sess == nil {
		return errorJSON(c, fiber.StatusUnauthorized, "unauthorized", "")
	}
	if err := h.svc.Logout(c.UserContext(), sess.Token); err != nil {
		return mapServiceErr(c, err)
	}
	return c.Status(fiber.StatusNoContent).Send(nil)
}

func (h *Handlers) Me(c *fiber.Ctx) error {
	user := UserFromCtx(c)
	if user == nil {
		return errorJSON(c, fiber.StatusUnauthorized, "unauthorized", "")
	}
	return c.Status(fiber.StatusOK).JSON(userDTO{
		ID:          user.ID.String(),
		Username:    user.Username,
		DisplayName: user.DisplayName,
	})
}

func (h *Handlers) UpdateMe(c *fiber.Ctx) error {
	user := UserFromCtx(c)
	if user == nil {
		return errorJSON(c, fiber.StatusUnauthorized, "unauthorized", "")
	}
	var body updateMeReq
	if err := c.BodyParser(&body); err != nil {
		return errorJSON(c, fiber.StatusBadRequest, "validation_failed", "invalid json body")
	}
	if err := h.svc.UpdateDisplayName(c.UserContext(), user.ID, body.DisplayName); err != nil {
		return mapServiceErr(c, err)
	}
	updated, err := h.svc.users.GetByID(c.UserContext(), user.ID)
	if err != nil {
		return mapServiceErr(c, err)
	}
	return c.Status(fiber.StatusOK).JSON(userDTO{
		ID:          updated.ID.String(),
		Username:    updated.Username,
		DisplayName: updated.DisplayName,
	})
}

func (h *Handlers) ChangePassword(c *fiber.Ctx) error {
	user := UserFromCtx(c)
	if user == nil {
		return errorJSON(c, fiber.StatusUnauthorized, "unauthorized", "")
	}
	var body changePasswordReq
	if err := c.BodyParser(&body); err != nil {
		return errorJSON(c, fiber.StatusBadRequest, "validation_failed", "invalid json body")
	}
	if err := h.svc.ChangePassword(c.UserContext(), user.ID, body.OldPassword, body.NewPassword); err != nil {
		return mapServiceErr(c, err)
	}
	return c.Status(fiber.StatusNoContent).Send(nil)
}

func mapServiceErr(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, domain.ErrValidation):
		return errorJSON(c, fiber.StatusBadRequest, "validation_failed", err.Error())
	case errors.Is(err, domain.ErrConsentRequired):
		return errorJSON(c, fiber.StatusBadRequest, "consent_required", "")
	case errors.Is(err, domain.ErrInvalidCredentials):
		return errorJSON(c, fiber.StatusUnauthorized, "invalid_credentials", "")
	case errors.Is(err, domain.ErrUnauthorized), errors.Is(err, domain.ErrTokenInvalid):
		return errorJSON(c, fiber.StatusUnauthorized, "unauthorized", "")
	case errors.Is(err, domain.ErrTokenExpired):
		return errorJSON(c, fiber.StatusUnauthorized, "token_expired", "")
	case errors.Is(err, domain.ErrConflict):
		return errorJSON(c, fiber.StatusConflict, "conflict", "")
	case errors.Is(err, domain.ErrRateLimited):
		return errorJSON(c, fiber.StatusTooManyRequests, "rate_limited", "")
	case errors.Is(err, domain.ErrNotFound):
		return errorJSON(c, fiber.StatusNotFound, "not_found", "")
	default:
		return errorJSON(c, fiber.StatusInternalServerError, "internal", "")
	}
}

func errorJSON(c *fiber.Ctx, status int, code, detail string) error {
	body := fiber.Map{"error": code}
	if detail != "" {
		body["detail"] = detail
	}
	return c.Status(status).JSON(body)
}
