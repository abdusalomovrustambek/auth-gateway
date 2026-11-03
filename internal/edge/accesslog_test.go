package edge

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func init() { gin.SetMode(gin.TestMode) }

func logRouter(buf *bytes.Buffer) *gin.Engine {
	r := gin.New()
	r.Use(ClientIP(ParseTrusted("10.0.0.0/8")), AccessLog(buf))
	r.POST("/auth/login", func(c *gin.Context) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
	})
	return r
}

func TestAccessLogLine(t *testing.T) {
	var buf bytes.Buffer
	r := logRouter(&buf)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"email":"alice@example.com","password":"hunter2-hunter2"}`))
	req.RemoteAddr = "10.0.0.5:4242"
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	req.Header.Set("User-Agent", "okhttp/4.12")
	req.Header.Set("Referer", "https://shop.agnts.uz/login")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	line := buf.String()
	if strings.Count(line, "\n") != 1 || !strings.HasSuffix(line, "\n") {
		t.Fatalf("want exactly one line, got %q", line)
	}
	pattern := regexp.MustCompile(`^203\.0\.113\.7 - - \[\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\] "POST /auth/login HTTP/1\.1" 401 (\d+) "https://shop\.agnts\.uz/login" "okhttp/4\.12"\n$`)
	m := pattern.FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("line is not in the combined format: %q", line)
	}
	if want := rec.Body.Len(); m[1] != strconv.Itoa(want) {
		t.Errorf("logged size %s, response body is %d bytes", m[1], want)
	}
	for _, secret := range []string{"alice@example.com", "hunter2"} {
		if strings.Contains(line, secret) {
			t.Errorf("log line contains %q", secret)
		}
	}
}

func TestAccessLogDashesAndPeerAddress(t *testing.T) {
	var buf bytes.Buffer
	r := logRouter(&buf)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	req.RemoteAddr = "198.51.100.9:1111"
	req.Header.Set("X-Forwarded-For", "6.6.6.6") // peer is not trusted
	req.Header.Del("User-Agent")
	r.ServeHTTP(httptest.NewRecorder(), req)

	if line := buf.String(); !strings.HasPrefix(line, "198.51.100.9 - - [") || !strings.HasSuffix(line, ` 401 `+strconv.Itoa(len(`{"error":"invalid email or password"}`))+" \"-\" \"-\"\n") {
		t.Errorf("line = %q", line)
	}
}

func TestAccessLogEscapesAndLogsEveryRequest(t *testing.T) {
	var buf bytes.Buffer
	r := logRouter(&buf)

	req := httptest.NewRequest(http.MethodGet, "/missing", nil)
	req.RemoteAddr = "198.51.100.9:1111"
	req.Header.Set("User-Agent", "evil\" 200 0 \"x\nfake line")
	r.ServeHTTP(httptest.NewRecorder(), req)

	if got := strings.Count(buf.String(), "\n"); got != 1 {
		t.Fatalf("a header forged %d lines: %q", got, buf.String())
	}
	if !strings.Contains(buf.String(), `"evil\" 200 0 \"x\x0afake line"`) {
		t.Errorf("user agent not escaped: %q", buf.String())
	}
	if !strings.Contains(buf.String(), `" 404 `) {
		t.Errorf("a request without a route is logged with its status: %q", buf.String())
	}
}

func TestAccessLogWritesLineWhenHandlerPanics(t *testing.T) {
	var buf bytes.Buffer
	r := gin.New()
	r.Use(AccessLog(&buf), gin.Recovery())
	r.GET("/boom", func(c *gin.Context) { panic("boom") })

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if !strings.Contains(buf.String(), `"GET /boom HTTP/1.1" 500 `) {
		t.Errorf("line = %q", buf.String())
	}
}

