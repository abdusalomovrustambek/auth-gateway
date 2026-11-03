package migrations

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
)

// Schema is the Postgres schema that holds every table of the service.
const Schema = "auth"

// schemaLockKey serialises schema creation between instances starting at once.
const schemaLockKey = 7283564109

// Open connects to the database with search_path set to schema, creating the
// schema first when it is missing. Goose needs the schema before it can make
// its own version table, so this cannot be a migration.
func Open(ctx context.Context, databaseURL, schema string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema

	if err := ensureSchema(ctx, cfg.ConnConfig, schema); err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect to database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return pool, nil
}

func ensureSchema(ctx context.Context, cfg *pgx.ConnConfig, schema string) error {
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	defer conn.Close(ctx)

	tx, err := conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin schema setup: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, schemaLockKey); err != nil {
		return fmt.Errorf("lock schema setup: %w", err)
	}
	// CREATE SCHEMA IF NOT EXISTS still needs CREATE on the database, which the
	// auth role may lack once the schema exists, so look first.
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)`, schema).Scan(&exists); err != nil {
		return fmt.Errorf("look up schema %q: %w", schema, err)
	}
	if !exists {
		if _, err := tx.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
			return fmt.Errorf("create schema %q: %w", schema, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit schema setup: %w", err)
	}
	return nil
}

// Up applies every pending migration. Goose takes a Postgres advisory lock for
// the run, so two instances starting at once are serialised.
func Up(ctx context.Context, pool *pgxpool.Pool) error {
	db := stdlib.OpenDB(*pool.Config().ConnConfig)
	defer db.Close()

	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return fmt.Errorf("create migration locker: %w", err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, db, FS, goose.WithSessionLocker(locker))
	if err != nil {
		return fmt.Errorf("create migration provider: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}
	return nil
}
