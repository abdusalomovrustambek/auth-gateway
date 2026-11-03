package account

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdusalomovrustambek/auth-gateway/internal/httpx"
	"github.com/abdusalomovrustambek/auth-gateway/internal/limit"
	"github.com/abdusalomovrustambek/auth-gateway/internal/testutil"
	"github.com/abdusalomovrustambek/auth-gateway/internal/token"
)

func init() { gin.SetMode(gin.TestMode) }

const testPassword = "correct-horse-1"

type testEnv struct {
	t      *testing.T
	router *gin.Engine
	pool   *pgxpool.Pool
	logs   *bytes.Buffer
}

// newEnv builds the /auth routes on a throwaway schema. With limited, the
// per-IP limiters of the gateway wrap /auth/login and /auth/register.
func newEnv(t *testing.T, limited bool) *testEnv {
	t.Helper()
	pool := testutil.NewPool(t)
	key, err := token.LoadOrCreateKey(context.Background(), pool, "test-secret")
	if err != nil {
		t.Fatalf("LoadOrCreateKey: %v", err)
	}
	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	svc, err := NewService(NewStore(pool), logger)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	issuer := token.NewIssuer(key)
	h := NewHandler(svc, issuer, token.NewRefresh(pool), logger)

	r := gin.New()
	r.Use(httpx.RequestID())
	if limited {
		ip := func(c *gin.Context) string { return httpx.ClientIP(c) }
		r.Use(
			limit.OnPath("/auth/login", limit.Middleware(limit.Per(10, time.Minute), ip)),
			limit.OnPath("/auth/register", limit.Middleware(limit.Per(5, time.Hour), ip)),
		)
	}
	h.Routes(r)
	r.GET("/.well-known/jwks.json", token.JWKS(key))
	return &testEnv{t: t, router: r, pool: pool, logs: logs}
}

func (e *testEnv) do(method, path string, body any, mods ...func(*http.Request)) *httptest.ResponseRecorder {
	var rd *strings.Reader
	switch b := body.(type) {
	case nil:
		rd = strings.NewReader("")
	case string:
		rd = strings.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			e.t.Errorf("marshal request body: %v", err)
		}
		rd = strings.NewReader(string(raw))
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "okhttp/4.12")
	for _, m := range mods {
		m(req)
	}
	rec := httptest.NewRecorder()
	e.router.ServeHTTP(rec, req)
	return rec
}

func withCookie(value string) func(*http.Request) {
	return func(r *http.Request) { r.AddCookie(&http.Cookie{Name: "refresh_token", Value: value}) }
}

func withBearer(tok string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
}

func cookieOf(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == "refresh_token" {
			return c
		}
	}
	t.Fatalf("no refresh_token cookie in response (status %d)", rec.Code)
	return nil
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return v
}

func credentials(email, password string) map[string]string {
	return map[string]string{"email": email, "password": password}
}

func register(t *testing.T, e *testEnv, email string) sessionJSON {
	t.Helper()
	rec := e.do(http.MethodPost, "/auth/register", map[string]string{"email": email, "password": testPassword, "name": "Test User"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("register %s: status %d, body %s", email, rec.Code, rec.Body)
	}
	return decode[sessionJSON](t, rec)
}

func TestRegisterLoginMeRefreshLogout(t *testing.T) {
	e := newEnv(t, false)

	reg := e.do(http.MethodPost, "/auth/register", map[string]string{"email": "  Alice@Example.com ", "password": testPassword, "name": " Alice "})
	if reg.Code != http.StatusCreated {
		t.Fatalf("register: status %d, body %s", reg.Code, reg.Body)
	}
	regSession := decode[sessionJSON](t, reg)
	if regSession.AccessToken == "" || regSession.TokenType != "Bearer" || regSession.ExpiresIn != 900 {
		t.Errorf("register session = %+v", regSession)
	}
	if regSession.User.Email != "alice@example.com" || regSession.User.Name != "Alice" {
		t.Errorf("register user = %+v, want trimmed and lower-cased", regSession.User)
	}

	// Login finds the same user with either case.
	login := e.do(http.MethodPost, "/auth/login", credentials("ALICE@example.com", testPassword))
	if login.Code != http.StatusOK {
		t.Fatalf("login: status %d, body %s", login.Code, login.Body)
	}
	session := decode[sessionJSON](t, login)
	if session.User.ID != regSession.User.ID {
		t.Errorf("login user id %q, register user id %q", session.User.ID, regSession.User.ID)
	}
	loginCookie := cookieOf(t, login)

	me := e.do(http.MethodGet, "/auth/me", nil, withBearer(session.AccessToken))
	if me.Code != http.StatusOK {
		t.Fatalf("me: status %d, body %s", me.Code, me.Body)
	}
	if u := decode[userJSON](t, me); u.Email != "alice@example.com" || u.ID != session.User.ID {
		t.Errorf("me = %+v", u)
	}

	refresh := e.do(http.MethodPost, "/auth/refresh", nil, withCookie(loginCookie.Value))
	if refresh.Code != http.StatusOK {
		t.Fatalf("refresh: status %d, body %s", refresh.Code, refresh.Body)
	}
	refreshed := decode[sessionJSON](t, refresh)
	if refreshed.AccessToken == "" {
		t.Error("refresh returned no access token")
	}
	rotated := cookieOf(t, refresh)
	if rotated.Value == "" || rotated.Value == loginCookie.Value {
		t.Errorf("refresh cookie was not rotated")
	}

	// The old cookie is spent and gets cleared.
	old := e.do(http.MethodPost, "/auth/refresh", nil, withCookie(loginCookie.Value))
	if old.Code != http.StatusUnauthorized {
		t.Errorf("refresh with a rotated cookie: status %d, want 401", old.Code)
	}
	if c := cookieOf(t, old); c.MaxAge >= 0 || c.Value != "" {
		t.Errorf("failed refresh did not clear the cookie: %+v", c)
	}

	logout := e.do(http.MethodPost, "/auth/logout", nil, withCookie(rotated.Value))
	if logout.Code != http.StatusNoContent {
		t.Fatalf("logout: status %d", logout.Code)
	}
	if c := cookieOf(t, logout); c.MaxAge >= 0 {
		t.Errorf("logout did not clear the cookie: %+v", c)
	}
	after := e.do(http.MethodPost, "/auth/refresh", nil, withCookie(rotated.Value))
	if after.Code != http.StatusUnauthorized {
		t.Errorf("refresh after logout: status %d, want 401", after.Code)
	}
}

func TestRefreshCookieAttributes(t *testing.T) {
	e := newEnv(t, false)
	rec := e.do(http.MethodPost, "/auth/register", map[string]string{"email": "a@example.com", "password": testPassword, "name": "A"})
	c := cookieOf(t, rec)
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != "/auth" {
		t.Errorf("cookie = %+v, want HttpOnly; Secure; SameSite=Strict; Path=/auth", c)
	}
	if c.MaxAge != 30*24*3600 {
		t.Errorf("Max-Age = %d, want 30 days", c.MaxAge)
	}

	var ua, ip string
	err := e.pool.QueryRow(context.Background(), `SELECT user_agent, ip FROM refresh_tokens`).Scan(&ua, &ip)
	if err != nil {
		t.Fatalf("read refresh token row: %v", err)
	}
	if ua != "okhttp/4.12" || ip != "192.0.2.1" {
		t.Errorf("user_agent, ip = %q, %q", ua, ip)
	}
}

func TestAccessTokenVerifiesAgainstJWKS(t *testing.T) {
	e := newEnv(t, false)
	session := register(t, e, "a@example.com")

	rec := e.do(http.MethodGet, "/.well-known/jwks.json", nil)
	set := decode[struct {
		Keys []struct {
			Kty, Crv, Kid, X string
		} `json:"keys"`
	}](t, rec)
	if len(set.Keys) != 1 || set.Keys[0].Kty != "OKP" || set.Keys[0].Crv != "Ed25519" || set.Keys[0].Kid == "" {
		t.Fatalf("jwks = %s", rec.Body)
	}
	x, err := base64.RawURLEncoding.DecodeString(set.Keys[0].X)
	if err != nil {
		t.Fatalf("decode x: %v", err)
	}

	var claims token.Claims
	parsed, err := jwt.ParseWithClaims(session.AccessToken, &claims, func(*jwt.Token) (any, error) {
		return ed25519.PublicKey(x), nil
	}, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer("shop.agnts.uz"), jwt.WithAudience("shop-api"))
	if err != nil || !parsed.Valid {
		t.Fatalf("token does not verify against the JWKS: %v", err)
	}
	if parsed.Header["kid"] != set.Keys[0].Kid {
		t.Errorf("token kid %v, jwks kid %s", parsed.Header["kid"], set.Keys[0].Kid)
	}
	if got := claims.ExpiresAt.Sub(claims.IssuedAt.Time); got != 15*time.Minute {
		t.Errorf("exp - iat = %v, want 15m", got)
	}
}

func TestRegisterAndLoginErrors(t *testing.T) {
	e := newEnv(t, false)
	register(t, e, "alice@example.com")

	tests := []struct {
		name   string
		path   string
		body   any
		status int
	}{
		{"duplicate email", "/auth/register", map[string]string{"email": "alice@example.com", "password": testPassword, "name": "A"}, http.StatusConflict},
		{"duplicate email in mixed case", "/auth/register", map[string]string{"email": " ALICE@Example.COM", "password": testPassword, "name": "A"}, http.StatusConflict},
		{"short password", "/auth/register", map[string]string{"email": "b@example.com", "password": "123456789", "name": "B"}, http.StatusBadRequest},
		{"missing name", "/auth/register", map[string]string{"email": "b@example.com", "password": testPassword, "name": "  "}, http.StatusBadRequest},
		{"bad email", "/auth/register", map[string]string{"email": "not-an-email", "password": testPassword, "name": "B"}, http.StatusBadRequest},
		{"malformed json", "/auth/register", `{"email": `, http.StatusBadRequest},
		{"wrong json type", "/auth/register", `{"email": 5}`, http.StatusBadRequest},
		{"empty body", "/auth/register", ``, http.StatusBadRequest},
		{"login malformed json", "/auth/login", `nope`, http.StatusBadRequest},
		{"wrong password", "/auth/login", credentials("alice@example.com", "wrong-password-1"), http.StatusUnauthorized},
		{"unknown email", "/auth/login", credentials("nobody@example.com", testPassword), http.StatusUnauthorized},
		{"empty credentials", "/auth/login", credentials("", ""), http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := e.do(http.MethodPost, tt.path, tt.body)
			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.status, rec.Body)
			}
			if msg := decode[map[string]string](t, rec)["error"]; msg == "" {
				t.Errorf("body %s has no error message", rec.Body)
			}
			if tt.status >= 400 {
				for _, c := range rec.Result().Cookies() {
					if c.MaxAge >= 0 && c.Value != "" {
						t.Errorf("error response set a cookie: %+v", c)
					}
				}
			}
		})
	}

	var users int
	if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM users`).Scan(&users); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if users != 1 {
		t.Errorf("users = %d, want 1: a failed request created an account", users)
	}
}

func TestConcurrentRegistrationsCreateOneUser(t *testing.T) {
	e := newEnv(t, false)

	const n = 6
	codes := make([]int, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			email := "race@example.com"
			if i%2 == 1 {
				email = " RACE@example.com"
			}
			codes[i] = e.do(http.MethodPost, "/auth/register", map[string]string{"email": email, "password": testPassword, "name": "R"}).Code
		}()
	}
	close(start)
	wg.Wait()

	created, conflicts := 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			conflicts++
		}
	}
	if created != 1 || conflicts != n-1 {
		t.Errorf("status codes %v: want one 201 and %d 409", codes, n-1)
	}
	var users int
	if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM users`).Scan(&users); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if users != 1 {
		t.Errorf("users = %d, want 1", users)
	}
}

func TestRefreshWithoutValidCookie(t *testing.T) {
	e := newEnv(t, false)
	register(t, e, "a@example.com")

	// An expired token.
	login := e.do(http.MethodPost, "/auth/login", credentials("a@example.com", testPassword))
	expired := cookieOf(t, login).Value
	if _, err := e.pool.Exec(context.Background(), `UPDATE refresh_tokens SET expires_at = now() - interval '1 second'`); err != nil {
		t.Fatalf("expire tokens: %v", err)
	}

	tests := []struct {
		name string
		mods []func(*http.Request)
	}{
		{"no cookie", nil},
		{"unknown cookie", []func(*http.Request){withCookie("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")}},
		{"expired cookie", []func(*http.Request){withCookie(expired)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := e.do(http.MethodPost, "/auth/refresh", nil, tt.mods...)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", rec.Code)
			}
			if c := cookieOf(t, rec); c.MaxAge >= 0 || c.Value != "" {
				t.Errorf("cookie not cleared: %+v", c)
			}
		})
	}
}

func TestConcurrentRefreshRotatesOnce(t *testing.T) {
	e := newEnv(t, false)
	register(t, e, "a@example.com")
	login := e.do(http.MethodPost, "/auth/login", credentials("a@example.com", testPassword))
	cookie := cookieOf(t, login).Value

	const n = 6
	codes := make([]int, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			codes[i] = e.do(http.MethodPost, "/auth/refresh", nil, withCookie(cookie)).Code
		}()
	}
	close(start)
	wg.Wait()

	ok, denied := 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusUnauthorized:
			denied++
		}
	}
	if ok != 1 || denied != n-1 {
		t.Errorf("status codes %v: want one 200 and %d 401", codes, n-1)
	}
}

func TestMeRequiresValidBearer(t *testing.T) {
	e := newEnv(t, false)
	session := register(t, e, "a@example.com")

	if rec := e.do(http.MethodGet, "/auth/me", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("no token: status %d, want 401", rec.Code)
	}
	if rec := e.do(http.MethodGet, "/auth/me", nil, withBearer(session.AccessToken+"x")); rec.Code != http.StatusUnauthorized {
		t.Errorf("tampered token: status %d, want 401", rec.Code)
	}

	// A valid token for a user that no longer exists.
	if _, err := e.pool.Exec(context.Background(), `DELETE FROM users`); err != nil {
		t.Fatalf("delete users: %v", err)
	}
	if rec := e.do(http.MethodGet, "/auth/me", nil, withBearer(session.AccessToken)); rec.Code != http.StatusUnauthorized {
		t.Errorf("deleted user: status %d, want 401", rec.Code)
	}
}

func TestLockoutAfterFiveWrongPasswords(t *testing.T) {
	e := newEnv(t, false)
	register(t, e, "bob@example.com")
	ctx := context.Background()

	for i := range 5 {
		rec := e.do(http.MethodPost, "/auth/login", credentials("bob@example.com", fmt.Sprintf("wrong-password-%d", i)))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("wrong password %d: status %d, want 401", i+1, rec.Code)
		}
	}

	// Locked: even the right password gets 429.
	rec := e.do(http.MethodPost, "/auth/login", credentials("bob@example.com", testPassword))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("right password while locked: status %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 has no Retry-After")
	}
	var lockedFor float64
	err := e.pool.QueryRow(ctx,
		`SELECT EXTRACT(EPOCH FROM (locked_until - now()))::float8 FROM users WHERE email = 'bob@example.com'`).Scan(&lockedFor)
	if err != nil {
		t.Fatalf("read locked_until: %v", err)
	}
	if lockedFor < 14*60 || lockedFor > 15*60 {
		t.Errorf("locked for %.0f seconds, want about 15 minutes", lockedFor)
	}
	if !strings.Contains(e.logs.String(), "account locked") {
		t.Errorf("no 'account locked' event in the log: %s", e.logs)
	}

	// The lock runs out: the right password works and resets the counter.
	if _, err := e.pool.Exec(ctx, `UPDATE users SET locked_until = now() - interval '1 minute'`); err != nil {
		t.Fatalf("expire lock: %v", err)
	}
	if rec := e.do(http.MethodPost, "/auth/login", credentials("bob@example.com", testPassword)); rec.Code != http.StatusOK {
		t.Fatalf("login after the lock expired: status %d, body %s", rec.Code, rec.Body)
	}
	var (
		failed int
		until  *time.Time
	)
	if err := e.pool.QueryRow(ctx, `SELECT failed_logins, locked_until FROM users`).Scan(&failed, &until); err != nil {
		t.Fatalf("read counters: %v", err)
	}
	if failed != 0 || until != nil {
		t.Errorf("failed_logins, locked_until = %d, %v, want 0, nil", failed, until)
	}
}

func TestFailuresAreConsecutiveAndLockExpiryRestartsCount(t *testing.T) {
	e := newEnv(t, false)
	register(t, e, "bob@example.com")
	ctx := context.Background()
	failedLogins := func() int {
		t.Helper()
		var n int
		if err := e.pool.QueryRow(ctx, `SELECT failed_logins FROM users`).Scan(&n); err != nil {
			t.Fatalf("read failed_logins: %v", err)
		}
		return n
	}

	for range 4 {
		e.do(http.MethodPost, "/auth/login", credentials("bob@example.com", "wrong-password-1"))
	}
	if got := failedLogins(); got != 4 {
		t.Fatalf("failed_logins = %d, want 4", got)
	}
	// A success in between starts the count again, so the account is not locked.
	if rec := e.do(http.MethodPost, "/auth/login", credentials("bob@example.com", testPassword)); rec.Code != http.StatusOK {
		t.Fatalf("login: status %d", rec.Code)
	}
	if got := failedLogins(); got != 0 {
		t.Errorf("failed_logins after a success = %d, want 0", got)
	}

	// After an expired lock, a wrong password counts as the first failure.
	if _, err := e.pool.Exec(ctx, `UPDATE users SET failed_logins = 5, locked_until = now() - interval '1 second'`); err != nil {
		t.Fatalf("set expired lock: %v", err)
	}
	if rec := e.do(http.MethodPost, "/auth/login", credentials("bob@example.com", "wrong-password-1")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password after expiry: status %d, want 401", rec.Code)
	}
	if got := failedLogins(); got != 1 {
		t.Errorf("failed_logins = %d, want 1", got)
	}
}

func TestUnknownEmailKeepsNoState(t *testing.T) {
	e := newEnv(t, false)
	for range 7 {
		if rec := e.do(http.MethodPost, "/auth/login", credentials("ghost@example.com", "whatever-password")); rec.Code != http.StatusUnauthorized {
			t.Fatalf("status %d, want 401: an unknown email must never be locked", rec.Code)
		}
	}
	var users int
	if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM users`).Scan(&users); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if users != 0 {
		t.Errorf("users = %d, want 0", users)
	}
}

func TestPerIPLimits(t *testing.T) {
	e := newEnv(t, true)

	for i := range 10 {
		if rec := e.do(http.MethodPost, "/auth/login", credentials("nobody@example.com", "whatever-password")); rec.Code != http.StatusUnauthorized {
			t.Fatalf("login %d: status %d, want 401", i+1, rec.Code)
		}
	}
	rec := e.do(http.MethodPost, "/auth/login", credentials("nobody@example.com", "whatever-password"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("11th login in a minute: status %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 has no Retry-After")
	}

	for i := range 5 {
		email := fmt.Sprintf("user%d@example.com", i)
		if rec := e.do(http.MethodPost, "/auth/register", map[string]string{"email": email, "password": testPassword, "name": "U"}); rec.Code != http.StatusCreated {
			t.Fatalf("register %d: status %d, body %s", i+1, rec.Code, rec.Body)
		}
	}
	rec = e.do(http.MethodPost, "/auth/register", map[string]string{"email": "user5@example.com", "password": testPassword, "name": "U"})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("6th register in an hour: status %d, want 429", rec.Code)
	}
}
