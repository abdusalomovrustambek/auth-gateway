// Package testutil has helpers shared by tests that need Postgres.
package testutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdusalomovrustambek/auth-gateway/migrations"
)

// NewPool returns a pool on a throwaway, migrated schema of the database in
// TEST_DATABASE_URL and drops the schema when the test ends. The test fails
// when the variable is not set.
func NewPool(t testing.TB) *pgxpool.Pool {
	t.Helper()
	pool, _ := NewPoolURL(t)
	return pool
}

// NewPoolURL is NewPool that also returns the database URL the pool uses.
func NewPoolURL(t testing.TB) (*pgxpool.Pool, string) {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Fatal("TEST_DATABASE_URL is not set: point it at a Postgres database the tests may create schemas in")
	}

	ctx := context.Background()
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("random schema name: %v", err)
	}
	schema := "t_" + hex.EncodeToString(buf)

	pool, err := migrations.Open(ctx, url, schema)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		conn, err := pgx.Connect(context.Background(), url)
		if err != nil {
			t.Errorf("connect to drop schema %s: %v", schema, err)
			return
		}
		defer conn.Close(context.Background())
		if _, err := conn.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+pgx.Identifier{schema}.Sanitize()+" CASCADE"); err != nil {
			t.Errorf("drop schema %s: %v", schema, err)
		}
	})
	if err := migrations.Up(ctx, pool); err != nil {
		t.Fatalf("migrate test schema: %v", err)
	}
	return pool, url
}
