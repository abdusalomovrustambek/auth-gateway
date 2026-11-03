package httpx

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() { gin.SetMode(gin.TestMode) }

func TestRequestID(t *testing.T) {
	r := gin.New()
	r.Use(RequestID())
	r.GET("/", func(c *gin.Context) { c.String(http.StatusOK, RequestIDFrom(c.Request.Context())) })

	tests := []struct {
		name     string
		incoming string
		keep     bool
	}{
		{"valid id is kept", "abc-123_DEF.4", true},
		{"max length is kept", strings.Repeat("a", 64), true},
		{"too long is replaced", strings.Repeat("a", 65), false},
		{"spaces are replaced", "has space", false},
		{"newline is replaced", "line\nbreak", false},
		{"quotes are replaced", `a"b`, false},
		{"missing is generated", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.incoming != "" {
				req.Header.Set(RequestIDHeader, tt.incoming)
			}
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)

			got := rec.Header().Get(RequestIDHeader)
			if got == "" || rec.Body.String() != got {
				t.Fatalf("header %q, context %q: want the same non-empty id", got, rec.Body)
			}
			if tt.keep && got != tt.incoming {
				t.Errorf("id = %q, want %q kept", got, tt.incoming)
			}
			if !tt.keep && got == tt.incoming {
				t.Errorf("id %q should have been replaced", got)
			}
			if !validRequestID(got) {
				t.Errorf("generated id %q is not valid", got)
			}
		})
	}
}

func TestErrorShape(t *testing.T) {
	r := gin.New()
	r.GET("/", func(c *gin.Context) { Error(c, http.StatusTeapot, "short and stout") })

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusTeapot || rec.Body.String() != `{"error":"short and stout"}` {
		t.Errorf("status %d, body %s", rec.Code, rec.Body)
	}
}

func TestClientIP(t *testing.T) {
	r := gin.New()
	r.GET("/stored", func(c *gin.Context) {
		SetClientIP(c, "203.0.113.7")
		c.String(http.StatusOK, ClientIP(c)+" "+ClientIPFrom(c.Request.Context()))
	})
	r.GET("/peer", func(c *gin.Context) { c.String(http.StatusOK, ClientIP(c)) })

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/stored", nil))
	if got := rec.Body.String(); got != "203.0.113.7 203.0.113.7" {
		t.Errorf("stored: %q", got)
	}
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/peer", nil))
	if got := rec.Body.String(); got != "192.0.2.1" {
		t.Errorf("peer fallback: %q, want 192.0.2.1", got)
	}
}
