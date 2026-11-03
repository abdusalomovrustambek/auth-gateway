package token

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RefreshTTL is how long a refresh token lives.
const RefreshTTL = 30 * 24 * time.Hour

// ErrInvalidRefresh is returned for a refresh token that is unknown, expired,
// already rotated or revoked.
var ErrInvalidRefresh = errors.New("token: invalid refresh token")

// Refresh stores refresh tokens. Only SHA-256 hashes reach the database.
type Refresh struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

// NewRefresh returns a Refresh store on pool.
func NewRefresh(pool *pgxpool.Pool) *Refresh {
	return &Refresh{pool: pool, now: time.Now}
}

// Issue makes a refresh token for the user and returns its raw value.
func (r *Refresh) Issue(ctx context.Context, userID, userAgent, ip string) (string, error) {
	raw, err := newRaw()
	if err != nil {
		return "", err
	}
	if err := r.insert(ctx, r.pool, raw, userID, userAgent, ip); err != nil {
		return "", err
	}
	return raw, nil
}

// Rotate marks the token as used and returns the user id and a new token, in
// one transaction. The row is locked, so of two simultaneous calls with the
// same token exactly one succeeds and the other gets ErrInvalidRefresh.
func (r *Refresh) Rotate(ctx context.Context, raw, userAgent, ip string) (userID, newToken string, err error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return "", "", fmt.Errorf("begin rotate: %w", err)
	}
	defer tx.Rollback(ctx)

	now := r.now()
	var (
		expiresAt time.Time
		rotatedAt *time.Time
	)
	err = tx.QueryRow(ctx,
		`SELECT user_id::text, expires_at, rotated_at FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE`,
		hashToken(raw)).Scan(&userID, &expiresAt, &rotatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrInvalidRefresh
	}
	if err != nil {
		return "", "", fmt.Errorf("lock refresh token: %w", err)
	}
	if rotatedAt != nil || !expiresAt.After(now) {
		return "", "", ErrInvalidRefresh
	}

	if _, err := tx.Exec(ctx, `UPDATE refresh_tokens SET rotated_at = $2 WHERE token_hash = $1`, hashToken(raw), now); err != nil {
		return "", "", fmt.Errorf("mark refresh token rotated: %w", err)
	}
	newToken, err = newRaw()
	if err != nil {
		return "", "", err
	}
	if err := r.insert(ctx, tx, newToken, userID, userAgent, ip); err != nil {
		return "", "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", "", fmt.Errorf("commit rotate: %w", err)
	}
	return userID, newToken, nil
}

// Revoke makes the token unusable. An unknown token is not an error.
func (r *Refresh) Revoke(ctx context.Context, raw string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE refresh_tokens SET rotated_at = COALESCE(rotated_at, $2) WHERE token_hash = $1`,
		hashToken(raw), r.now())
	if err != nil {
		return fmt.Errorf("revoke refresh token: %w", err)
	}
	return nil
}

type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func (r *Refresh) insert(ctx context.Context, db execer, raw, userID, userAgent, ip string) error {
	_, err := db.Exec(ctx,
		`INSERT INTO refresh_tokens (token_hash, user_id, expires_at, user_agent, ip) VALUES ($1, $2::uuid, $3, $4, $5)`,
		hashToken(raw), userID, r.now().Add(RefreshTTL), userAgent, ip)
	if err != nil {
		return fmt.Errorf("store refresh token: %w", err)
	}
	return nil
}

func newRaw() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("make refresh token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashToken(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}
