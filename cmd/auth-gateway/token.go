package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/abdusalomovrustambek/auth-gateway/internal/account"
	"github.com/abdusalomovrustambek/auth-gateway/internal/token"
	"github.com/abdusalomovrustambek/auth-gateway/migrations"
)

// tokenOptions are the inputs of `auth-gateway token`.
type tokenOptions struct {
	Email    string
	TTL      time.Duration
	Password string
}

// parseTokenArgs reads --email and --ttl, and the password from
// AUTH_TOKEN_PASSWORD.
func parseTokenArgs(args []string, getenv func(string) string) (tokenOptions, error) {
	flags := flag.NewFlagSet("token", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	email := flags.String("email", "", "email of the account (created when missing)")
	ttl := flags.Duration("ttl", token.DefaultAccessTTL, "lifetime of the token, such as 24h")
	if err := flags.Parse(args); err != nil {
		return tokenOptions{}, fmt.Errorf("token: %w (usage: auth-gateway token --email <email> [--ttl 24h])", err)
	}
	if flags.NArg() > 0 {
		return tokenOptions{}, fmt.Errorf("token: unexpected argument %q", flags.Arg(0))
	}
	opts := tokenOptions{Email: strings.TrimSpace(*email), TTL: *ttl, Password: getenv("AUTH_TOKEN_PASSWORD")}
	if opts.Email == "" {
		return tokenOptions{}, errors.New("token: --email is required")
	}
	if opts.TTL <= 0 {
		return tokenOptions{}, errors.New("token: --ttl must be positive")
	}
	if opts.Password == "" {
		return tokenOptions{}, errors.New("token: AUTH_TOKEN_PASSWORD is not set")
	}
	return opts, nil
}

// runToken connects like the server does and prints an access token.
func runToken(ctx context.Context, args []string, getenv func(string) string, stdout io.Writer) error {
	opts, err := parseTokenArgs(args, getenv)
	if err != nil {
		return err
	}
	cfg, err := loadConfig(getenv, false)
	if err != nil {
		return err
	}
	// stdout carries the token only, so events go to stderr.
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	pool, err := migrations.Open(ctx, cfg.DatabaseURL, migrations.Schema)
	if err != nil {
		return err
	}
	defer pool.Close()
	return issueToken(ctx, pool, cfg.KeySecret, opts, logger, stdout)
}

// issueToken signs in the account, creating it when it does not exist, and
// prints an access token that lives for opts.TTL.
func issueToken(ctx context.Context, pool *pgxpool.Pool, keySecret string, opts tokenOptions, log *slog.Logger, stdout io.Writer) error {
	key, err := prepare(ctx, pool, keySecret)
	if err != nil {
		return err
	}
	svc, err := account.NewService(account.NewStore(pool), log)
	if err != nil {
		return err
	}

	name, _, _ := strings.Cut(account.NormalizeEmail(opts.Email), "@")
	user, err := svc.Register(ctx, opts.Email, opts.Password, name)
	if errors.Is(err, account.ErrDuplicateEmail) {
		user, err = svc.Login(ctx, opts.Email, opts.Password)
	}
	if err != nil {
		return fmt.Errorf("token: sign in %s: %w", opts.Email, err)
	}

	issuer := token.NewIssuer(key, token.WithTTL(opts.TTL))
	raw, err := issuer.Issue(user.ID, user.Email, user.Name)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(stdout, raw); err != nil {
		return fmt.Errorf("token: write token: %w", err)
	}
	return nil
}
