package edge

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

const (
	htmlAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	indexBody  = "<html>shop</html>"
	secretBody = "outside-the-root"
	dotBody    = "DATABASE_URL=postgres://secret\n"
)

func writeFile(t *testing.T, name, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(name, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func staticRouter(t *testing.T) *gin.Engine {
	t.Helper()
	tmp := t.TempDir()
	root := filepath.Join(tmp, "web")
	writeFile(t, filepath.Join(root, "index.html"), indexBody)
	writeFile(t, filepath.Join(root, "assets", "app.js"), "console.log(1)")
	writeFile(t, filepath.Join(root, "robots.txt"), "User-agent: *")
	writeFile(t, filepath.Join(root, ".env"), dotBody)
	writeFile(t, filepath.Join(root, ".git", "config"), "[core]")
	writeFile(t, filepath.Join(tmp, "secret.txt"), secretBody)

	r := gin.New()
	r.NoRoute(Static(root))
	return r
}

func TestStatic(t *testing.T) {
	r := staticRouter(t)

	tests := []struct {
		name   string
		method string
		path   string
		accept string
		status int
		body   string // exact body when non-empty
	}{
		{"existing js file", http.MethodGet, "/assets/app.js", "*/*", http.StatusOK, "console.log(1)"},
		{"existing file without accept", http.MethodGet, "/robots.txt", "", http.StatusOK, "User-agent: *"},
		{"existing file with html accept", http.MethodGet, "/robots.txt", htmlAccept, http.StatusOK, "User-agent: *"},
		{"spa route gets index", http.MethodGet, "/products/42", htmlAccept, http.StatusOK, indexBody},
		{"root gets index", http.MethodGet, "/", htmlAccept, http.StatusOK, indexBody},
		{"index.html by name", http.MethodGet, "/index.html", "*/*", http.StatusOK, indexBody},
		{"directory with html accept gets index", http.MethodGet, "/assets", htmlAccept, http.StatusOK, indexBody},
		{"spa route without html accept", http.MethodGet, "/products/42", "", http.StatusNotFound, ""},
		{"spa route with json accept", http.MethodGet, "/products/42", "application/json", http.StatusNotFound, ""},
		{"spa route with any accept", http.MethodGet, "/products/42", "*/*", http.StatusNotFound, ""},
		{"scanner path with extension", http.MethodGet, "/wp-login.php", htmlAccept, http.StatusNotFound, ""},
		{"scanner path without accept", http.MethodGet, "/wp-login.php", "", http.StatusNotFound, ""},
		{"missing js file", http.MethodGet, "/missing.js", htmlAccept, http.StatusNotFound, ""},
		{"missing file without accept", http.MethodGet, "/missing.js", "", http.StatusNotFound, ""},
		{"post is not served", http.MethodPost, "/products/42", htmlAccept, http.StatusNotFound, ""},
		{"post to an existing file", http.MethodPost, "/robots.txt", "*/*", http.StatusNotFound, ""},
		{"traversal", http.MethodGet, "/../secret.txt", "*/*", http.StatusNotFound, ""},
		{"traversal encoded", http.MethodGet, "/%2e%2e/secret.txt", "*/*", http.StatusNotFound, ""},
		{"traversal in the middle", http.MethodGet, "/assets/../../secret.txt", "*/*", http.StatusNotFound, ""},
		{"dotfile", http.MethodGet, "/.env", "*/*", http.StatusNotFound, ""},
		{"dotfile with html accept", http.MethodGet, "/.env", htmlAccept, http.StatusNotFound, ""},
		{"head dotfile", http.MethodHead, "/.env", "*/*", http.StatusNotFound, ""},
		{"dot directory file", http.MethodGet, "/.git/config", "*/*", http.StatusNotFound, ""},
		{"traversal to dotfile", http.MethodGet, "/assets/../.env", "*/*", http.StatusNotFound, ""},
		{"encoded dotfile", http.MethodGet, "/%2Eenv", "*/*", http.StatusNotFound, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)

			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d (body %q)", rec.Code, tt.status, rec.Body)
			}
			if tt.body != "" && rec.Body.String() != tt.body {
				t.Errorf("body = %q, want %q", rec.Body, tt.body)
			}
			if strings.Contains(rec.Body.String(), secretBody) {
				t.Error("response leaked a file outside the root")
			}
			if strings.Contains(rec.Body.String(), dotBody) {
				t.Error("response leaked a dotfile under the root")
			}
		})
	}
}

func TestStaticHeadAndContentType(t *testing.T) {
	r := staticRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/products/42", nil)
	req.Header.Set("Accept", htmlAccept)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("index Content-Type = %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("index Cache-Control = %q, want no-cache", cc)
	}

	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodHead, "/assets/app.js", nil))
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("HEAD: status %d, body %q", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "javascript") {
		t.Errorf("js Content-Type = %q", ct)
	}
}

func TestStaticExplicitRouteWinsOverDotGuard(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, ".well-known", "x"), "dot file must not serve")

	r := gin.New()
	r.GET("/.well-known/jwks.json", func(c *gin.Context) { c.String(http.StatusOK, "jwks") })
	r.NoRoute(Static(root))

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "jwks" {
		t.Errorf("explicit dot route: status %d, body %q, want 200 %q", rec.Code, rec.Body, "jwks")
	}

	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/x", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("static dot path: status %d, want 404", rec.Code)
	}
}

func TestStaticWithoutIndex(t *testing.T) {
	r := gin.New()
	r.NoRoute(Static(t.TempDir()))

	req := httptest.NewRequest(http.MethodGet, "/products/42", nil)
	req.Header.Set("Accept", htmlAccept)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404 when index.html is missing", rec.Code)
	}
}
