package httpx

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"

	"github.com/gin-gonic/gin"
)

// RequestIDHeader carries the request id on requests and responses.
const RequestIDHeader = "X-Request-ID"

const (
	maxRequestIDLen = 64
	clientIPKey     = "httpx.client_ip"
)

type requestIDKey struct{}

// RequestID keeps a valid incoming X-Request-ID or makes a new one, and puts it
// on the request context and the response.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader(RequestIDHeader)
		if !validRequestID(id) {
			id = newRequestID()
		}
		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), requestIDKey{}, id))
		c.Header(RequestIDHeader, id)
		c.Next()
	}
}

// RequestIDFrom returns the request id stored by RequestID, or "".
func RequestIDFrom(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey{}).(string)
	return id
}

// validRequestID accepts 1 to 64 letters, digits, '-', '_' and '.'.
func validRequestID(id string) bool {
	if id == "" || len(id) > maxRequestIDLen {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
		default:
			return false
		}
	}
	return true
}

func newRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand does not fail on supported platforms; an id is still
		// better than none.
		return "unknown"
	}
	return hex.EncodeToString(b)
}

type clientIPCtxKey struct{}

// SetClientIP stores the resolved client IP on the Gin context and on the
// request context, for later handlers and for the reverse proxy.
func SetClientIP(c *gin.Context, ip string) {
	c.Set(clientIPKey, ip)
	c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), clientIPCtxKey{}, ip))
}

// ClientIPFrom returns the IP stored by SetClientIP on a request context, or "".
func ClientIPFrom(ctx context.Context) string {
	ip, _ := ctx.Value(clientIPCtxKey{}).(string)
	return ip
}

// ClientIP returns the IP stored by SetClientIP, or the host of the peer
// address when none was stored.
func ClientIP(c *gin.Context) string {
	if ip := c.GetString(clientIPKey); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
	if err != nil {
		return c.Request.RemoteAddr
	}
	return host
}

