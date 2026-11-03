package account

import (
	"errors"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/abdusalomovrustambek/auth-gateway/internal/httpx"
	"github.com/abdusalomovrustambek/auth-gateway/internal/token"
)

const (
	refreshCookie   = "refresh_token"
	refreshPath     = "/auth"
	maxBodyBytes    = 1 << 14
	maxUserAgentLen = 255
)

// Handler serves the /auth endpoints. It binds requests and shapes responses;
// the rules live in Service and the token package.
type Handler struct {
	svc     *Service
	access  *token.Issuer
	refresh *token.Refresh
	log     *slog.Logger
}

// NewHandler returns a Handler.
func NewHandler(svc *Service, access *token.Issuer, refresh *token.Refresh, log *slog.Logger) *Handler {
	return &Handler{svc: svc, access: access, refresh: refresh, log: log}
}

// Routes registers the /auth endpoints on r.
func (h *Handler) Routes(r gin.IRouter) {
	r.POST("/auth/register", h.Register)
	r.POST("/auth/login", h.Login)
	r.POST("/auth/refresh", h.Refresh)
	r.POST("/auth/logout", h.Logout)
	r.GET("/auth/me", token.Bearer(h.access), h.Me)
}

type userJSON struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

type sessionJSON struct {
	AccessToken string   `json:"access_token"`
	TokenType   string   `json:"token_type"`
	ExpiresIn   int      `json:"expires_in"`
	User        userJSON `json:"user"`
}

func toUserJSON(u User) userJSON {
	return userJSON{ID: u.ID, Email: u.Email, Name: u.Name}
}

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Register handles POST /auth/register.
func (h *Handler) Register(c *gin.Context) {
	var req registerRequest
	if !h.bind(c, &req) {
		return
	}
	user, err := h.svc.Register(c.Request.Context(), req.Email, req.Password, req.Name)
	var invalid *InvalidInputError
	switch {
	case errors.As(err, &invalid):
		httpx.Error(c, http.StatusBadRequest, invalid.Message)
		return
	case errors.Is(err, ErrDuplicateEmail):
		httpx.Error(c, http.StatusConflict, "could not create the account")
		return
	case err != nil:
		h.fail(c, "register", err)
		return
	}
	h.startSession(c, http.StatusCreated, user)
}

// Login handles POST /auth/login.
func (h *Handler) Login(c *gin.Context) {
	var req loginRequest
	if !h.bind(c, &req) {
		return
	}
	user, err := h.svc.Login(c.Request.Context(), req.Email, req.Password)
	var locked *LockedError
	switch {
	case errors.As(err, &locked):
		if wait := time.Until(locked.Until); wait > 0 {
			c.Header("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
		}
		httpx.Error(c, http.StatusTooManyRequests, "too many failed attempts, try again later")
		return
	case errors.Is(err, ErrInvalidCredentials):
		httpx.Error(c, http.StatusUnauthorized, "invalid email or password")
		return
	case err != nil:
		h.fail(c, "login", err)
		return
	}
	h.startSession(c, http.StatusOK, user)
}

// Refresh handles POST /auth/refresh: the cookie is exchanged for a new access
// token and a rotated cookie. Any failure clears the cookie.
func (h *Handler) Refresh(c *gin.Context) {
	ctx := c.Request.Context()
	raw, err := c.Cookie(refreshCookie)
	if err != nil || raw == "" {
		h.unauthorizedRefresh(c)
		return
	}
	userID, next, err := h.refresh.Rotate(ctx, raw, userAgent(c), httpx.ClientIP(c))
	if errors.Is(err, token.ErrInvalidRefresh) {
		h.unauthorizedRefresh(c)
		return
	}
	if err != nil {
		h.clearRefreshCookie(c)
		h.fail(c, "refresh", err)
		return
	}
	user, err := h.svc.Get(ctx, userID)
	if errors.Is(err, ErrNotFound) {
		h.unauthorizedRefresh(c)
		return
	}
	if err != nil {
		h.clearRefreshCookie(c)
		h.fail(c, "refresh", err)
		return
	}
	access, err := h.access.Issue(user.ID, user.Email, user.Name)
	if err != nil {
		h.clearRefreshCookie(c)
		h.fail(c, "refresh", err)
		return
	}
	h.setRefreshCookie(c, next)
	c.JSON(http.StatusOK, h.session(access, user))
}

// Logout handles POST /auth/logout: it revokes the refresh token and clears the
// cookie.
func (h *Handler) Logout(c *gin.Context) {
	if raw, err := c.Cookie(refreshCookie); err == nil && raw != "" {
		if err := h.refresh.Revoke(c.Request.Context(), raw); err != nil {
			h.clearRefreshCookie(c)
			h.fail(c, "logout", err)
			return
		}
	}
	h.clearRefreshCookie(c)
	c.Status(http.StatusNoContent)
}

// Me handles GET /auth/me; the bearer middleware has verified the token.
func (h *Handler) Me(c *gin.Context) {
	claims, ok := token.ClaimsFrom(c)
	if !ok {
		httpx.Error(c, http.StatusUnauthorized, "invalid token")
		return
	}
	user, err := h.svc.Get(c.Request.Context(), claims.Subject)
	if errors.Is(err, ErrNotFound) {
		httpx.Error(c, http.StatusUnauthorized, "invalid token")
		return
	}
	if err != nil {
		h.fail(c, "me", err)
		return
	}
	c.JSON(http.StatusOK, toUserJSON(user))
}

// bind reads a small JSON body into dst, or answers 400.
func (h *Handler) bind(c *gin.Context, dst any) bool {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)
	if err := c.ShouldBindJSON(dst); err != nil {
		httpx.Error(c, http.StatusBadRequest, "request body must be valid JSON")
		return false
	}
	return true
}

// startSession issues the access token and refresh cookie for a signed-in user.
func (h *Handler) startSession(c *gin.Context, status int, user User) {
	ctx := c.Request.Context()
	access, err := h.access.Issue(user.ID, user.Email, user.Name)
	if err != nil {
		h.fail(c, "start session", err)
		return
	}
	refresh, err := h.refresh.Issue(ctx, user.ID, userAgent(c), httpx.ClientIP(c))
	if err != nil {
		h.fail(c, "start session", err)
		return
	}
	h.setRefreshCookie(c, refresh)
	c.JSON(status, h.session(access, user))
}

func (h *Handler) session(access string, user User) sessionJSON {
	return sessionJSON{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   int(h.access.TTL().Seconds()),
		User:        toUserJSON(user),
	}
}

func (h *Handler) unauthorizedRefresh(c *gin.Context) {
	h.clearRefreshCookie(c)
	httpx.Error(c, http.StatusUnauthorized, "invalid refresh token")
}

func (h *Handler) setRefreshCookie(c *gin.Context, value string) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     refreshCookie,
		Value:    value,
		Path:     refreshPath,
		MaxAge:   int(token.RefreshTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func (h *Handler) clearRefreshCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     refreshCookie,
		Value:    "",
		Path:     refreshPath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// fail logs an unexpected error once and answers 500 without detail.
func (h *Handler) fail(c *gin.Context, op string, err error) {
	h.log.Error("auth request failed", "op", op, "request_id", httpx.RequestIDFrom(c.Request.Context()), "error", err)
	httpx.Error(c, http.StatusInternalServerError, "internal error")
}

// userAgent returns the User-Agent cut to a length and character set Postgres
// text accepts.
func userAgent(c *gin.Context) string {
	ua := c.Request.UserAgent()
	if len(ua) > maxUserAgentLen {
		ua = ua[:maxUserAgentLen]
	}
	return strings.ReplaceAll(strings.ToValidUTF8(ua, ""), "\x00", "")
}
