package edge

import (
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/abdusalomovrustambek/auth-gateway/internal/httpx"
)

// Proxy forwards requests to target (SHOP_API_URL), keeping the request path
// as it is, so /api/products becomes <target>/api/products. X-Forwarded-For is
// overwritten with the resolved client IP and X-Request-ID is set; the
// Authorization header passes through. If the upstream cannot be reached it
// logs `proxy error` and answers 502.
func Proxy(target *url.URL, log *slog.Logger) gin.HandlerFunc {
	transport := &http.Transport{}
	if base, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = base.Clone()
	}
	transport.DialContext = (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	transport.ResponseHeaderTimeout = 30 * time.Second

	rp := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			host := pr.In.Host
			pr.SetURL(target)
			pr.Out.Host = host
			// ReverseProxy has already dropped any client-supplied
			// X-Forwarded-* headers from the outbound request.
			if ip := httpx.ClientIPFrom(pr.In.Context()); ip != "" {
				pr.Out.Header.Set("X-Forwarded-For", ip)
			}
			if id := httpx.RequestIDFrom(pr.In.Context()); id != "" {
				pr.Out.Header.Set(httpx.RequestIDHeader, id)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Error("proxy error",
				"error", err,
				"method", r.Method,
				"path", r.URL.Path,
				"request_id", httpx.RequestIDFrom(r.Context()))
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			if _, werr := w.Write([]byte(`{"error":"bad gateway"}`)); werr != nil {
				log.Error("proxy error response", "error", werr)
			}
		},
	}
	return func(c *gin.Context) {
		rp.ServeHTTP(c.Writer, c.Request)
	}
}
