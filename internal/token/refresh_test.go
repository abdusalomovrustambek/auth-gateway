package token

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdusalomovrustambek/auth-gateway/internal/testutil"
)

func newUser(t *testing.T, pool *pgxpool.Pool, email string) string {
	t.Helper()
	var id string
	err := pool.QueryRow(context.Background(),
		`INSERT INTO users (email, password_hash, name) VALUES ($1, 'x', 'Test') RETURNING id::text`, email).Scan(&id)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	return id
}

func TestRotateGivesNewTokenAndKillsOld(t *testing.T) {
	ctx := context.Background()
	pool := testutil.NewPool(t)
	store := NewRefresh(pool)
	uid := newUser(t, pool, "a@example.com")

	first, err := store.Issue(ctx, uid, "agent/1", "203.0.113.7")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	gotUID, second, err := store.Rotate(ctx, first, "agent/2", "203.0.113.8")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if gotUID != uid {
		t.Errorf("user id = %q, want %q", gotUID, uid)
	}
	if second == "" || second == first {
		t.Errorf("rotated token %q should differ from %q", second, first)
	}
	if _, _, err := store.Rotate(ctx, first, "", ""); !errors.Is(err, ErrInvalidRefresh) {
		t.Errorf("rotating the old token again: err = %v, want ErrInvalidRefresh", err)
	}
	if _, _, err := store.Rotate(ctx, second, "", ""); err != nil {
		t.Errorf("rotating the new token: %v", err)
	}

	var ua, ip string
	err = pool.QueryRow(ctx, `SELECT user_agent, ip FROM refresh_tokens WHERE token_hash = $1`, hashToken(second)).Scan(&ua, &ip)
	if err != nil {
		t.Fatalf("read second token row: %v", err)
	}
	if ua != "agent/2" || ip != "203.0.113.8" {
		t.Errorf("user_agent, ip = %q, %q", ua, ip)
	}
}

func TestRotateRejects(t *testing.T) {
	ctx := context.Background()
	pool := testutil.NewPool(t)
	store := NewRefresh(pool)
	uid := newUser(t, pool, "a@example.com")

	expired, err := store.Issue(ctx, uid, "", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE refresh_tokens SET expires_at = now() - interval '1 second' WHERE token_hash = $1`, hashToken(expired)); err != nil {
		t.Fatalf("expire: %v", err)
	}
	revoked, err := store.Issue(ctx, uid, "", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := store.Revoke(ctx, revoked); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	tests := []struct {
		name string
		raw  string
	}{
		{"expired", expired},
		{"revoked", revoked},
		{"unknown", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"empty", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := store.Rotate(ctx, tt.raw, "", ""); !errors.Is(err, ErrInvalidRefresh) {
				t.Errorf("err = %v, want ErrInvalidRefresh", err)
			}
		})
	}
	if err := store.Revoke(ctx, "unknown-token"); err != nil {
		t.Errorf("Revoke of an unknown token: %v", err)
	}
}

func TestOnlyHashesAreStored(t *testing.T) {
	ctx := context.Background()
	pool := testutil.NewPool(t)
	store := NewRefresh(pool)
	uid := newUser(t, pool, "a@example.com")

	raw, err := store.Issue(ctx, uid, "", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	var stored []byte
	if err := pool.QueryRow(ctx, `SELECT token_hash FROM refresh_tokens`).Scan(&stored); err != nil {
		t.Fatalf("read token_hash: %v", err)
	}
	sum := sha256.Sum256([]byte(raw))
	if !bytes.Equal(stored, sum[:]) {
		t.Errorf("token_hash is not the SHA-256 of the token")
	}
	if bytes.Contains(stored, []byte(raw)) {
		t.Error("raw token found in token_hash")
	}
}

func TestConcurrentRotationSucceedsOnce(t *testing.T) {
	ctx := context.Background()
	pool := testutil.NewPool(t)
	store := NewRefresh(pool)
	uid := newUser(t, pool, "a@example.com")
	raw, err := store.Issue(ctx, uid, "", "")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	const n = 8
	var (
		wg        sync.WaitGroup
		mu        sync.Mutex
		successes int
		failures  int
	)
	start := make(chan struct{})
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _, err := store.Rotate(ctx, raw, "", "")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				successes++
			case errors.Is(err, ErrInvalidRefresh):
				failures++
			default:
				t.Errorf("unexpected error: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if successes != 1 || failures != n-1 {
		t.Errorf("successes = %d, failures = %d, want 1 and %d", successes, failures, n-1)
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM refresh_tokens`).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 2 {
		t.Errorf("refresh_tokens rows = %d, want 2 (the original and one rotation)", rows)
	}
}

func TestSigningKeyCreatedOnce(t *testing.T) {
	ctx := context.Background()
	pool := testutil.NewPool(t)

	const n = 6
	keys := make([]*Key, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			keys[i], errs[i] = LoadOrCreateKey(ctx, pool, "throwaway-secret")
		}()
	}
	close(start)
	wg.Wait()

	for i := range n {
		if errs[i] != nil {
			t.Fatalf("LoadOrCreateKey %d: %v", i, errs[i])
		}
		if keys[i].KID != keys[0].KID || !bytes.Equal(keys[i].Public, keys[0].Public) {
			t.Errorf("instance %d got a different key", i)
		}
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM signing_key`).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 1 {
		t.Errorf("signing_key rows = %d, want 1", rows)
	}

	again, err := LoadOrCreateKey(ctx, pool, "throwaway-secret")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if again.KID != keys[0].KID {
		t.Errorf("reloaded kid %q, want %q", again.KID, keys[0].KID)
	}
}

func TestSigningKeyRefusesWrongSecret(t *testing.T) {
	ctx := context.Background()
	pool := testutil.NewPool(t)
	if _, err := LoadOrCreateKey(ctx, pool, "right-secret"); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := LoadOrCreateKey(ctx, pool, "wrong-secret"); err == nil {
		t.Fatal("a wrong AUTH_KEY_SECRET loaded the key")
	}
	if _, err := LoadOrCreateKey(ctx, pool, ""); err == nil {
		t.Fatal("an empty AUTH_KEY_SECRET loaded the key")
	}

	// The stored key must be untouched: no new key was made over it.
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM signing_key`).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 1 {
		t.Errorf("signing_key rows = %d, want 1", rows)
	}
	if _, err := LoadOrCreateKey(ctx, pool, "right-secret"); err != nil {
		t.Errorf("right secret no longer loads the key: %v", err)
	}
}
