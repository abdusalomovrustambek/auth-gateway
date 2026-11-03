// Package token issues and verifies access JWTs, rotates refresh tokens, owns
// the signing key and serves the JWKS.
package token

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/hkdf"
)

// Key is the Ed25519 key pair that signs access tokens.
type Key struct {
	KID     string
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
}

var errNoKey = errors.New("token: no signing key stored")

// LoadOrCreateKey returns the signing key stored in auth.signing_key. On the
// first start it makes one, encrypted with a key derived from secret. Two
// instances starting at once end up with the same key: the insert keeps the
// first row and both reread it. A stored key that cannot be decrypted is an
// error; a new key is never made over it.
func LoadOrCreateKey(ctx context.Context, pool *pgxpool.Pool, secret string) (*Key, error) {
	if secret == "" {
		return nil, errors.New("token: AUTH_KEY_SECRET is empty")
	}
	aead, err := newAEAD(secret)
	if err != nil {
		return nil, err
	}

	key, err := loadKey(ctx, pool, aead)
	if err == nil {
		return key, nil
	}
	if !errors.Is(err, errNoKey) {
		return nil, err
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	enc, err := seal(aead, priv.Seed())
	if err != nil {
		return nil, err
	}
	_, err = pool.Exec(ctx,
		`INSERT INTO signing_key (id, kid, private_key_enc) VALUES (1, $1, $2) ON CONFLICT (id) DO NOTHING`,
		keyID(pub), enc)
	if err != nil {
		return nil, fmt.Errorf("store signing key: %w", err)
	}
	// Reread: if another instance won the insert, use its key.
	return loadKey(ctx, pool, aead)
}

func loadKey(ctx context.Context, pool *pgxpool.Pool, aead cipher.AEAD) (*Key, error) {
	var (
		kid string
		enc []byte
	)
	err := pool.QueryRow(ctx, `SELECT kid, private_key_enc FROM signing_key WHERE id = 1`).Scan(&kid, &enc)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNoKey
	}
	if err != nil {
		return nil, fmt.Errorf("load signing key: %w", err)
	}
	seed, err := open(aead, enc)
	if err != nil {
		return nil, fmt.Errorf("decrypt stored signing key (is AUTH_KEY_SECRET the one it was made with?): %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("stored signing key has %d bytes, want %d", len(seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	// The public half is the last 32 bytes of an Ed25519 private key.
	pub := ed25519.PublicKey(priv[ed25519.SeedSize:])
	return &Key{KID: kid, Private: priv, Public: pub}, nil
}

// newKey makes an in-memory key without touching the database.
func newKey() (*Key, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate signing key: %w", err)
	}
	return &Key{KID: keyID(pub), Private: priv, Public: pub}, nil
}

// keyID names a key by the first 8 bytes of the SHA-256 of its public half.
func keyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// newAEAD derives an AES-256-GCM cipher from secret with HKDF-SHA256.
func newAEAD(secret string) (cipher.AEAD, error) {
	k := make([]byte, 32)
	r := hkdf.New(sha256.New, []byte(secret), nil, []byte("auth-gateway signing key v1"))
	if _, err := io.ReadFull(r, k); err != nil {
		return nil, fmt.Errorf("derive key encryption key: %w", err)
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	return aead, nil
}

// seal returns nonce || ciphertext.
func seal(aead cipher.AEAD, plain []byte) ([]byte, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("make nonce: %w", err)
	}
	return aead.Seal(nonce, nonce, plain, nil), nil
}

func open(aead cipher.AEAD, enc []byte) ([]byte, error) {
	if len(enc) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := enc[:aead.NonceSize()], enc[aead.NonceSize():]
	return aead.Open(nil, nonce, ct, nil)
}
