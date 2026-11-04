package edge

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/abdusalomovrustambek/auth-gateway/internal/httpx"
)

// seen is what the fake shop-api received.
type seen struct {
	method, uri, auth, xff, requestID string
	body                              string
}

// upstream starts a fake shop-api and returns a function that reads the last
// request it received.
func upstream(t *testing.T) (*httptest.Server, func() seen) {
	t.Helper()
	var (
		mu  sync.Mutex
		got seen
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("upstream read body: %v", err)
		}
		mu.Lock()
		got = seen{
			method: r.Method, uri: r.RequestURI, auth: r.Header.Get("Authorization"),
			xff: r.Header.Get("X-Forwarded-For"), requestID: r.Header.Get("X-Request-ID"),
			body: string(b),
		}
		mu.Unlock()
		w.Header().Set("X-Upstream", "yes")
		w.WriteHeader(http.StatusCreated)
		if _, err := io.WriteString(w, `{"ok":true}`); err != nil {
			t.Errorf("upstream write: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() seen {
		mu.Lock()
		defer mu.Unlock()
		return got
	}
}

func proxyRouter(t *testing.T, target string, logs io.Writer) *gin.Engine {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatalf("parse %q: %v", target, err)
	}
	r := gin.New()
	r.Use(httpx.RequestID(), ClientIP(ParseTrusted("10.0.0.0/8")))
	r.Any("/api/*path", Proxy(u, slog.New(slog.NewJSONHandler(logs, nil))))
	return r
}

func TestProxyForwardsWithHeaders(t *testing.T) {
	srv, last := upstream(t)
	r := proxyRouter(t, srv.URL, io.Discard)

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		wantXFF    string
	}{
		{"trusted peer, client behind it", "10.0.0.5:1234", "203.0.113.7", "203.0.113.7"},
		{"untrusted peer, forged header is replaced", "198.51.100.9:5555", "6.6.6.6", "198.51.100.9"},
		{"untrusted peer without header", "198.51.100.9:5555", "", "198.51.100.9"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/products?limit=5", strings.NewReader(`{"a":1}`))
			req.RemoteAddr = tt.remoteAddr
			req.Header.Set("Authorization", "Bearer abc.def.ghi")
			req.Header.Set("X-Request-ID", "req-42")
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			got := last()

			if rec.Code != http.StatusCreated || rec.Body.String() != `{"ok":true}` || rec.Header().Get("X-Upstream") != "yes" {
				t.Fatalf("response: status %d, body %q", rec.Code, rec.Body)
			}
			if got.method != http.MethodPost || got.uri != "/api/products?limit=5" || got.body != `{"a":1}` {
				t.Errorf("upstream saw %s %s %q, want the /api prefix, query and body kept", got.method, got.uri, got.body)
			}
			if got.auth != "Bearer abc.def.ghi" {
				t.Errorf("Authorization = %q, want it passed through", got.auth)
			}
			if got.xff != tt.wantXFF {
				t.Errorf("X-Forwarded-For = %q, want %q", got.xff, tt.wantXFF)
			}
			if got.requestID != "req-42" {
				t.Errorf("X-Request-ID = %q, want req-42", got.requestID)
			}
		})
	}
}

func TestProxyMakesRequestID(t *testing.T) {
	srv, last := upstream(t)
	r := proxyRouter(t, srv.URL, io.Discard)

	req := httptest.NewRequest(http.MethodGet, "/api/ping", nil)
	req.RemoteAddr = "198.51.100.9:5555"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	got := last()

	if got.requestID == "" || got.requestID != rec.Header().Get("X-Request-ID") {
		t.Errorf("upstream X-Request-ID %q, response X-Request-ID %q: want the same generated id", got.requestID, rec.Header().Get("X-Request-ID"))
	}
}

func TestProxyKeepsPrefixUnderUpstreamBasePath(t *testing.T) {
	srv, last := upstream(t)
	r := proxyRouter(t, srv.URL+"/v1", io.Discard)

	r.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/orders", nil))
	got := last()
	if got.uri != "/v1/api/orders" {
		t.Errorf("upstream saw %q, want /v1/api/orders", got.uri)
	}
}

func TestProxyUpstreamDownGives502(t *testing.T) {
	srv, _ := upstream(t)
	dead := srv.URL
	srv.Close() // the port is now refused

	var logs bytes.Buffer
	r := proxyRouter(t, dead, &logs)

	req := httptest.NewRequest(http.MethodGet, "/api/products", nil)
	req.Header.Set("X-Request-ID", "req-99")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", rec.Code)
	}
	if rec.Body.String() != `{"error":"bad gateway"}` {
		t.Errorf("body = %q", rec.Body)
	}
	for _, want := range []string{`"msg":"proxy error"`, `"level":"ERROR"`, `"request_id":"req-99"`, `"path":"/api/products"`} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log %q does not contain %s", logs.String(), want)
		}
	}
}
