package token

import (
	"encoding/base64"
	"net/http"

	"github.com/gin-gonic/gin"
)

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	X   string `json:"x"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

// JWKS serves the public key as a JSON Web Key Set (OKP / Ed25519).
func JWKS(key *Key) gin.HandlerFunc {
	set := jwks{Keys: []jwk{{
		Kty: "OKP",
		Crv: "Ed25519",
		Kid: key.KID,
		Use: "sig",
		Alg: "EdDSA",
		X:   base64.RawURLEncoding.EncodeToString(key.Public),
	}}}
	return func(c *gin.Context) {
		c.Header("Cache-Control", "public, max-age=300")
		c.JSON(http.StatusOK, set)
	}
}
