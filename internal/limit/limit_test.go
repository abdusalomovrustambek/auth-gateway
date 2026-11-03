package limit

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func init() { gin.SetMode(gin.TestMode) }

func byRemoteHost(c *gin.Context) string { return c.Request.Header.Get("X-Test-Key") }

func do(r *gin.Engine, method, path, key string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("X-Test-Key", key)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestBucketAllowsBurstThenLimits(t *testing.T) {
	r := gin.New()
	r.Use(Middleware(Per(3, time.Minute), byRemoteHost))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusNoContent) })

	for i := range 3 {
		if rec := do(r, http.MethodGet, "/", "a"); rec.Code != http.StatusNoContent {
			t.Fatalf("request %d: status = %d, want 204", i+1, rec.Code)
		}
	}
	rec := do(r, http.MethodGet, "/", "a")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("4th request: status = %d, want 429", rec.Code)
	}
	secs, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	if err != nil || secs < 1 || secs > 60 {
		t.Errorf("Retry-After = %q, want 1..60 seconds", rec.Header().Get("Retry-After"))
	}
	if got := rec.Body.String(); got != `{"error":"too many requests"}` {
		t.Errorf("body = %s", got)
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l := Per(1, time.Hour)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("first request for a was limited")
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("second request for a was allowed")
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("first request for b was limited by a's bucket")
	}
}

func TestBucketRefills(t *testing.T) {
	l := Per(2, time.Minute) // one token every 30s
	now := time.Now()
	l.now = func() time.Time { return now }

	l.Allow("a")
	l.Allow("a")
	if ok, wait := l.Allow("a"); ok || wait <= 0 || wait > 30*time.Second {
		t.Fatalf("empty bucket: ok = %v, wait = %v", ok, wait)
	}
	now = now.Add(31 * time.Second)
	if ok, _ := l.Allow("a"); !ok {
		t.Error("bucket did not refill after 31s")
	}
}

func TestIdleEntriesAreEvicted(t *testing.T) {
	l := Per(3, time.Minute)
	now := time.Now()
	l.now = func() time.Time { return now }
	l.lastSweep = now

	l.Allow("a")
	l.Allow("b")
	if got := l.Len(); got != 2 {
		t.Fatalf("Len = %d, want 2", got)
	}
	now = now.Add(l.idle / 2)
	l.Allow("b") // keeps b alive
	now = now.Add(l.idle/2 + time.Second)
	l.Allow("c") // triggers the sweep: a is idle, b is not

	if got := l.Len(); got != 2 {
		t.Errorf("Len after sweep = %d, want 2 (b and c)", got)
	}
	if _, ok := l.entries["a"]; ok {
		t.Error("idle entry a was not evicted")
	}
}

func TestOnPathAppliesToThatPathOnly(t *testing.T) {
	r := gin.New()
	r.Use(OnPath("/limited", Middleware(Per(1, time.Hour), byRemoteHost)))
	ok := func(c *gin.Context) { c.Status(http.StatusNoContent) }
	r.GET("/limited", ok)
	r.GET("/other", ok)

	if rec := do(r, http.MethodGet, "/limited", "a"); rec.Code != http.StatusNoContent {
		t.Fatalf("first /limited: %d", rec.Code)
	}
	if rec := do(r, http.MethodGet, "/limited", "a"); rec.Code != http.StatusTooManyRequests {
		t.Errorf("second /limited: %d, want 429", rec.Code)
	}
	for _, p := range []string{"/other", "/other"} {
		if rec := do(r, http.MethodGet, p, "a"); rec.Code != http.StatusNoContent {
			t.Errorf("%s: %d, want 204 (not limited)", p, rec.Code)
		}
	}
}
