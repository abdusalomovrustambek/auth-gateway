package token

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/abdusalomovrustambek/auth-gateway/internal/httpx"
)

const claimsKey = "token.claims"

// Bearer requires a valid access token in the Authorization header and stores
// its claims for ClaimsFrom. Anything else is a 401.
func Bearer(issuer *Issuer) gin.HandlerFunc {
	return func(c *gin.Context) {
		scheme, raw, ok := strings.Cut(c.GetHeader("Authorization"), " ")
		raw = strings.TrimSpace(raw)
		if !ok || !strings.EqualFold(scheme, "Bearer") || raw == "" {
			c.Header("WWW-Authenticate", "Bearer")
			httpx.Error(c, http.StatusUnauthorized, "missing bearer token")
			return
		}
		claims, err := issuer.Verify(raw)
		if err != nil {
			c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
			httpx.Error(c, http.StatusUnauthorized, "invalid token")
			return
		}
		c.Set(claimsKey, claims)
		c.Next()
	}
}

// ClaimsFrom returns the claims stored by Bearer.
func ClaimsFrom(c *gin.Context) (*Claims, bool) {
	v, ok := c.Get(claimsKey)
	if !ok {
		return nil, false
	}
	claims, ok := v.(*Claims)
	return claims, ok
}
