package token

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func init() { gin.SetMode(gin.TestMode) }

func testKey(t *testing.T) *Key {
	t.Helper()
	key, err := newKey()
	if err != nil {
		t.Fatalf("newKey: %v", err)
	}
	return key
}

func validClaims(now time.Time) Claims {
	return Claims{
		Email: "alice@example.com",
		Name:  "Alice",
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "user-1",
			Issuer:    ClaimIssuer,
			Audience:  jwt.ClaimStrings{ClaimAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
		},
	}
}

func sign(t *testing.T, method jwt.SigningMethod, signKey any, kid string, claims Claims) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(signKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func TestIssueAndVerify(t *testing.T) {
	key := testKey(t)
	issuer := NewIssuer(key)

	raw, err := issuer.Issue("user-1", "alice@example.com", "Alice")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	claims, err := issuer.Verify(raw)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "user-1" || claims.Email != "alice@example.com" || claims.Name != "Alice" {
		t.Errorf("claims = %+v", claims)
	}
	if claims.Issuer != "shop.agnts.uz" {
		t.Errorf("iss = %q, want shop.agnts.uz", claims.Issuer)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "shop-api" {
		t.Errorf("aud = %v, want [shop-api]", claims.Audience)
	}
	if claims.IssuedAt == nil || claims.ExpiresAt == nil {
		t.Fatalf("iat/exp missing: %+v", claims.RegisteredClaims)
	}

	parsed, _, err := jwt.NewParser().ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if parsed.Header["kid"] != key.KID {
		t.Errorf("kid = %v, want %s", parsed.Header["kid"], key.KID)
	}
	if parsed.Header["alg"] != "EdDSA" {
		t.Errorf("alg = %v, want EdDSA", parsed.Header["alg"])
	}
}

func TestDefaultAndCustomTTL(t *testing.T) {
	key := testKey(t)
	tests := []struct {
		name string
		opts []Option
		want time.Duration
	}{
		{"default", nil, 15 * time.Minute},
		{"custom", []Option{WithTTL(24 * time.Hour)}, 24 * time.Hour},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer := NewIssuer(key, tt.opts...)
			raw, err := issuer.Issue("u", "a@b.c", "A")
			if err != nil {
				t.Fatalf("Issue: %v", err)
			}
			claims, err := issuer.Verify(raw)
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if got := claims.ExpiresAt.Sub(claims.IssuedAt.Time); got != tt.want {
				t.Errorf("exp - iat = %v, want %v", got, tt.want)
			}
			if issuer.TTL() != tt.want {
				t.Errorf("TTL() = %v, want %v", issuer.TTL(), tt.want)
			}
		})
	}
}

func TestVerifyRejects(t *testing.T) {
	key := testKey(t)
	other := testKey(t)
	issuer := NewIssuer(key)
	now := time.Now()

	wrongAud := validClaims(now)
	wrongAud.Audience = jwt.ClaimStrings{"other-api"}
	wrongIss := validClaims(now)
	wrongIss.Issuer = "evil.example"
	expired := validClaims(now.Add(-time.Hour))
	noExp := validClaims(now)
	noExp.ExpiresAt = nil

	valid := sign(t, jwt.SigningMethodEdDSA, key.Private, key.KID, validClaims(now))
	parts := strings.Split(valid, ".")
	tampered := strings.Join([]string{parts[0], parts[1], "Z" + parts[2][1:]}, ".")
	if parts[2][0] == 'Z' {
		tampered = strings.Join([]string{parts[0], parts[1], "Y" + parts[2][1:]}, ".")
	}

	enc := base64.RawURLEncoding
	noneHeader := enc.EncodeToString([]byte(`{"alg":"none","typ":"JWT","kid":"` + key.KID + `"}`))
	nonePayload := enc.EncodeToString([]byte(`{"sub":"user-1","iss":"shop.agnts.uz","aud":"shop-api","exp":` + "4102444800" + `}`))

	tests := []struct {
		name string
		raw  string
	}{
		{"expired", sign(t, jwt.SigningMethodEdDSA, key.Private, key.KID, expired)},
		{"wrong audience", sign(t, jwt.SigningMethodEdDSA, key.Private, key.KID, wrongAud)},
		{"wrong issuer", sign(t, jwt.SigningMethodEdDSA, key.Private, key.KID, wrongIss)},
		{"no expiry", sign(t, jwt.SigningMethodEdDSA, key.Private, key.KID, noExp)},
		{"tampered signature", tampered},
		{"other key", sign(t, jwt.SigningMethodEdDSA, other.Private, key.KID, validClaims(now))},
		{"unknown kid", sign(t, jwt.SigningMethodEdDSA, key.Private, "nope", validClaims(now))},
		{"no kid", sign(t, jwt.SigningMethodEdDSA, key.Private, "", validClaims(now))},
		{"alg none", noneHeader + "." + nonePayload + "."},
		{"alg HS256", sign(t, jwt.SigningMethodHS256, []byte("shared-secret"), key.KID, validClaims(now))},
		{"garbage", "not-a-token"},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := issuer.Verify(tt.raw); err == nil {
				t.Errorf("Verify accepted %s", tt.name)
			}
		})
	}
}

func TestVerifyExpiryFollowsClock(t *testing.T) {
	key := testKey(t)
	start := time.Now()
	clock := start
	issuer := NewIssuer(key, WithClock(func() time.Time { return clock }))

	raw, err := issuer.Issue("u", "a@b.c", "A")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	clock = start.Add(14 * time.Minute)
	if _, err := issuer.Verify(raw); err != nil {
		t.Errorf("Verify after 14m: %v", err)
	}
	clock = start.Add(16 * time.Minute)
	if _, err := issuer.Verify(raw); err == nil {
		t.Error("Verify accepted a token 16 minutes old")
	}
}

func TestBearerMiddleware(t *testing.T) {
	key := testKey(t)
	issuer := NewIssuer(key)
	now := time.Now()

	r := gin.New()
	r.GET("/me", Bearer(issuer), func(c *gin.Context) {
		claims, ok := ClaimsFrom(c)
		if !ok {
			c.Status(http.StatusInternalServerError)
			return
		}
		c.String(http.StatusOK, claims.Subject)
	})

	good, err := issuer.Issue("user-1", "a@b.c", "A")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	wrongAud := validClaims(now)
	wrongAud.Audience = jwt.ClaimStrings{"other-api"}
	expired := validClaims(now.Add(-time.Hour))

	tests := []struct {
		name   string
		header string
		want   int
	}{
		{"valid", "Bearer " + good, http.StatusOK},
		{"scheme is case-insensitive", "bearer " + good, http.StatusOK},
		{"missing", "", http.StatusUnauthorized},
		{"wrong scheme", "Basic " + good, http.StatusUnauthorized},
		{"empty token", "Bearer ", http.StatusUnauthorized},
		{"HS256", "Bearer " + sign(t, jwt.SigningMethodHS256, []byte("s"), key.KID, validClaims(now)), http.StatusUnauthorized},
		{"wrong audience", "Bearer " + sign(t, jwt.SigningMethodEdDSA, key.Private, key.KID, wrongAud), http.StatusUnauthorized},
		{"expired", "Bearer " + sign(t, jwt.SigningMethodEdDSA, key.Private, key.KID, expired), http.StatusUnauthorized},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/me", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			if rec.Code != tt.want {
				t.Errorf("status = %d, want %d (body %s)", rec.Code, tt.want, rec.Body)
			}
		})
	}
}

func TestJWKS(t *testing.T) {
	key := testKey(t)
	r := gin.New()
	r.GET("/.well-known/jwks.json", JWKS(key))

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var got jwks
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got.Keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(got.Keys))
	}
	k := got.Keys[0]
	if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Kid != key.KID || k.Use != "sig" || k.Alg != "EdDSA" {
		t.Errorf("jwk = %+v", k)
	}
	x, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil || !bytes.Equal(x, key.Public) {
		t.Errorf("x does not decode to the public key (err %v)", err)
	}
}
