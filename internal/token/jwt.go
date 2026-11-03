package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// The JWT contract with shop-api.
const (
	ClaimIssuer      = "shop.agnts.uz"
	ClaimAudience    = "shop-api"
	DefaultAccessTTL = 15 * time.Minute
)

// ErrInvalidToken is returned by Verify for any token it does not accept.
var ErrInvalidToken = errors.New("token: invalid access token")

// Claims are the claims of an access token: sub, email, name, iat, exp, iss, aud.
type Claims struct {
	Email string `json:"email"`
	Name  string `json:"name"`
	jwt.RegisteredClaims
}

// Issuer signs and verifies access tokens with one key.
type Issuer struct {
	key    *Key
	ttl    time.Duration
	now    func() time.Time
	parser *jwt.Parser
}

// Option changes an Issuer.
type Option func(*Issuer)

// WithTTL sets the lifetime of issued tokens. Only the token subcommand uses
// it; the server keeps DefaultAccessTTL.
func WithTTL(d time.Duration) Option {
	return func(i *Issuer) { i.ttl = d }
}

// WithClock replaces time.Now, for tests.
func WithClock(now func() time.Time) Option {
	return func(i *Issuer) { i.now = now }
}

// NewIssuer returns an Issuer for key.
func NewIssuer(key *Key, opts ...Option) *Issuer {
	i := &Issuer{key: key, ttl: DefaultAccessTTL, now: time.Now}
	for _, o := range opts {
		o(i)
	}
	i.parser = jwt.NewParser(
		jwt.WithValidMethods([]string{jwt.SigningMethodEdDSA.Alg()}),
		jwt.WithIssuer(ClaimIssuer),
		jwt.WithAudience(ClaimAudience),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(i.now),
	)
	return i
}

// TTL is the lifetime of the tokens this Issuer makes.
func (i *Issuer) TTL() time.Duration { return i.ttl }

// Issue signs an access token for the user.
func (i *Issuer) Issue(userID, email, name string) (string, error) {
	now := i.now()
	claims := Claims{
		Email: email,
		Name:  name,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    ClaimIssuer,
			Audience:  jwt.ClaimStrings{ClaimAudience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(i.ttl)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	tok.Header["kid"] = i.key.KID
	signed, err := tok.SignedString(i.key.Private)
	if err != nil {
		return "", fmt.Errorf("sign access token: %w", err)
	}
	return signed, nil
}

// Verify checks signature (EdDSA only), kid, iss, aud and exp, and returns the
// claims.
func (i *Issuer) Verify(raw string) (*Claims, error) {
	claims := &Claims{}
	_, err := i.parser.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		if kid, _ := t.Header["kid"].(string); kid != i.key.KID {
			return nil, errors.New("unknown kid")
		}
		return i.key.Public, nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidToken, err)
	}
	return claims, nil
}
