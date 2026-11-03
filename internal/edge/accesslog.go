package edge

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/abdusalomovrustambek/auth-gateway/internal/httpx"
)

// combinedTime is the timestamp layout of the combined log format.
const combinedTime = "02/Jan/2006:15:04:05 -0700"

// AccessLog writes one combined-format line per request to w:
//
//	203.0.113.7 - - [03/Nov/2026:10:00:00 +0000] "POST /auth/login HTTP/1.1" 401 52 "-" "okhttp/4.12"
//
// The client IP is the one resolved by ClientIP, so put this middleware after
// it. The line is written when the handlers have finished, even if one panics.
func AccessLog(w io.Writer) gin.HandlerFunc {
	var mu sync.Mutex
	return func(c *gin.Context) {
		start := time.Now()
		defer func() {
			size := max(c.Writer.Size(), 0)
			line := fmt.Sprintf("%s - - [%s] \"%s %s %s\" %d %d \"%s\" \"%s\"\n",
				httpx.ClientIP(c),
				start.Format(combinedTime),
				escape(c.Request.Method), escape(c.Request.RequestURI), escape(c.Request.Proto),
				c.Writer.Status(), size,
				dashIfEmpty(escape(c.Request.Referer())), dashIfEmpty(escape(c.Request.UserAgent())))
			mu.Lock()
			defer mu.Unlock()
			if _, err := io.WriteString(w, line); err != nil {
				slog.Error("write access log", "error", err)
			}
		}()
		c.Next()
	}
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// escape makes s safe inside a quoted log field: quotes, backslashes and
// control characters cannot start a new field or a new line.
func escape(s string) string {
	if !strings.ContainsAny(s, "\"\\") && !hasControl(s) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, "\\x%02x", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}
