package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/abdusalomovrustambek/auth-gateway/internal/testutil"
	"github.com/abdusalomovrustambek/auth-gateway/internal/token"
)

func init() { gin.SetMode(gin.TestMode) }

func TestLoadConfig(t *testing.T) {
	full := map[string]string{
		"DATABASE_URL":    "postgres://auth@localhost/shop",
		"AUTH_KEY_SECRET": "placeholder",
		"SHOP_API_URL":    "http://shop-api:8081",
	}
	without := func(name string) map[string]string {
		m := map[string]string{}
		for k, v := range full {
			if k != name {
				m[k] = v
			}
		}
		return m
	}

	tests := []struct {
		name    string
		env     map[string]string
		server  bool
		wantErr []string
	}{
		{"server with everything", full, true, nil},
		{"missing database url", without("DATABASE_URL"), true, []string{"DATABASE_URL"}},
		{"missing key secret", without("AUTH_KEY_SECRET"), true, []string{"AUTH_KEY_SECRET"}},
		{"missing upstream", without("SHOP_API_URL"), true, []string{"SHOP_API_URL"}},
		{"nothing set names every variable", nil, true, []string{"DATABASE_URL", "AUTH_KEY_SECRET", "SHOP_API_URL"}},
		{"blank value counts as missing", map[string]string{"DATABASE_URL": "  ", "AUTH_KEY_SECRET": "x", "SHOP_API_URL": "http://x"}, true, []string{"DATABASE_URL"}},
		{"token command does not need the upstream", without("SHOP_API_URL"), false, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := loadConfig(envOf(tt.env), tt.server)
			if len(tt.wantErr) > 0 {
				if err == nil {
					t.Fatal("want an error")
				}
				for _, name := range tt.wantErr {
					if !strings.Contains(err.Error(), name) {
						t.Errorf("error %q does not name %s", err, name)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cfg.Addr != ":8080" {
				t.Errorf("Addr = %q, want the :8080 default", cfg.Addr)
			}
		})
	}
}

func TestParseUpstream(t *testing.T) {
	tests := []struct {
		raw string
		ok  bool
	}{
		{"http://shop-api:8081", true},
		{"https://shop.example/base", true},
		{"shop-api:8081", false},
		{"ftp://shop-api", false},
		{"http://", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			if _, err := parseUpstream(tt.raw); (err == nil) != tt.ok {
				t.Errorf("parseUpstream(%q) error = %v, want ok = %v", tt.raw, err, tt.ok)
			}
		})
	}
}

func TestRouterWiring(t *testing.T) {
	ctx := context.Background()
	pool := testutil.NewPool(t)
	key, err := prepare(ctx, pool, "wiring-secret")
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	assets := t.TempDir()
	if err := os.WriteFile(filepath.Join(assets, "index.html"), []byte("<html>shop</html>"), 0o644); err != nil {
		t.Fatalf("write index: %v", err)
	}
	upstream, err := url.Parse("http://127.0.0.1:1")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var accessLog bytes.Buffer
	router, err := newRouter(routerDeps{
		cfg:       config{AssetsDir: assets, TrustedProxies: "10.0.0.0/8"},
		pool:      pool,
		key:       key,
		upstream:  upstream,
		log:       slog.New(slog.NewJSONHandler(io.Discard, nil)),
		accessLog: &accessLog,
	})
	if err != nil {
		t.Fatalf("newRouter: %v", err)
	}

	get := func(path, accept string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	if rec := get("/healthz", ""); rec.Code != http.StatusOK {
		t.Errorf("/healthz: status %d, want 200", rec.Code)
	}
	if rec := get("/.well-known/jwks.json", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), key.KID) {
		t.Errorf("/.well-known/jwks.json: status %d, body %s", rec.Code, rec.Body)
	}
	if rec := get("/products/42", "text/html"); rec.Code != http.StatusOK || rec.Body.String() != "<html>shop</html>" {
		t.Errorf("SPA route: status %d, body %q", rec.Code, rec.Body)
	}
	if rec := get("/wp-login.php", ""); rec.Code != http.StatusNotFound {
		t.Errorf("/wp-login.php: status %d, want 404", rec.Code)
	}
	if rec := get("/api/products", ""); rec.Code != http.StatusBadGateway {
		t.Errorf("/api with the upstream down: status %d, want 502", rec.Code)
	}

	// Register through the real router and use the token on /auth/me.
	body := strings.NewReader(`{"email":"wiring@example.com","password":"correct-horse-1","name":"W"}`)
	req := httptest.NewRequest(http.MethodPost, "/auth/register", body)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: status %d, body %s", rec.Code, rec.Body)
	}
	if lines := strings.Count(accessLog.String(), "\n"); lines != 6 {
		t.Errorf("access log has %d lines for 6 requests:\n%s", lines, accessLog.String())
	}
	if strings.Contains(accessLog.String(), "wiring@example.com") {
		t.Error("access log contains the email")
	}

	// A closed pool makes the health check fail.
	pool.Close()
	if rec := get("/healthz", ""); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("/healthz with the database gone: status %d, want 503", rec.Code)
	}
}

func TestLoginPerIPLimit(t *testing.T) {
	// No database: the router is built with a nil pool and an in-memory
	// key, and malformed bodies fail binding with 400 before any handler
	// can touch the pool. Every attempt still passes the real limiter
	// chain from newRouter, spending a per-IP token without tripping the
	// per-email lockout.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	upstream, err := url.Parse("http://127.0.0.1:1")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	router, err := newRouter(routerDeps{
		cfg:       config{AssetsDir: t.TempDir(), TrustedProxies: "10.0.0.0/8"},
		pool:      nil,
		key:       &token.Key{KID: "test-kid", Private: priv, Public: pub},
		upstream:  upstream,
		log:       slog.New(slog.NewJSONHandler(io.Discard, nil)),
		accessLog: io.Discard,
	})
	if err != nil {
		t.Fatalf("newRouter: %v", err)
	}

	post := func(path string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`nope`))
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		return rec
	}

	for i := range 10 {
		if rec := post("/auth/login"); rec.Code != http.StatusBadRequest {
			t.Fatalf("login attempt %d: status %d, want 400", i+1, rec.Code)
		}
	}
	if rec := post("/auth/login"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("11th login attempt: status %d, want 429 (per-IP login limit)", rec.Code)
	} else if rec.Header().Get("Retry-After") == "" {
		t.Error("login 429 has no Retry-After header")
	}

	// The register limiter next door keeps its own budget.
	for i := range 5 {
		if rec := post("/auth/register"); rec.Code != http.StatusBadRequest {
			t.Fatalf("register attempt %d: status %d, want 400", i+1, rec.Code)
		}
	}
	if rec := post("/auth/register"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("6th register attempt: status %d, want 429 (per-IP register limit)", rec.Code)
	} else if rec.Header().Get("Retry-After") == "" {
		t.Error("register 429 has no Retry-After header")
	}
}

