package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/abdusalomovrustambek/auth-gateway/internal/account"
	"github.com/abdusalomovrustambek/auth-gateway/internal/testutil"
	"github.com/abdusalomovrustambek/auth-gateway/internal/token"
)

const (
	cliSecret     = "cli-test-secret"
	cliPassword   = "swagger-password-1"
	otherPassword = "placeholder-other-pw"
)

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestParseTokenArgs(t *testing.T) {
	withPassword := map[string]string{"AUTH_TOKEN_PASSWORD": cliPassword}
	tests := []struct {
		name    string
		args    []string
		env     map[string]string
		want    tokenOptions
		wantErr string
	}{
		{"email and ttl", []string{"--email", "swagger@shop.test", "--ttl", "24h"}, withPassword,
			tokenOptions{Email: "swagger@shop.test", TTL: 24 * time.Hour, Password: cliPassword}, ""},
		{"default ttl", []string{"--email=swagger@shop.test"}, withPassword,
			tokenOptions{Email: "swagger@shop.test", TTL: 15 * time.Minute, Password: cliPassword}, ""},
		{"missing email", []string{"--ttl", "24h"}, withPassword, tokenOptions{}, "--email is required"},
		{"blank email", []string{"--email", "  "}, withPassword, tokenOptions{}, "--email is required"},
		{"unparseable ttl", []string{"--email", "a@b.test", "--ttl", "tomorrow"}, withPassword, tokenOptions{}, "invalid value"},
		{"zero ttl", []string{"--email", "a@b.test", "--ttl", "0s"}, withPassword, tokenOptions{}, "--ttl must be positive"},
		{"negative ttl", []string{"--email", "a@b.test", "--ttl", "-1h"}, withPassword, tokenOptions{}, "--ttl must be positive"},
		{"missing password", []string{"--email", "a@b.test"}, nil, tokenOptions{}, "AUTH_TOKEN_PASSWORD"},
		{"unknown flag", []string{"--nope"}, withPassword, tokenOptions{}, "flag provided but not defined"},
		{"positional argument", []string{"--email", "a@b.test", "extra"}, withPassword, tokenOptions{}, "unexpected argument"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTokenArgs(tt.args, envOf(tt.env))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("options = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestIssueTokenCreatesThenSignsIn(t *testing.T) {
	ctx := context.Background()
	pool := testutil.NewPool(t)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	opts := tokenOptions{Email: "swagger@shop.test", TTL: 24 * time.Hour, Password: cliPassword}

	verify := func(raw string) *token.Claims {
		t.Helper()
		key, err := token.LoadOrCreateKey(ctx, pool, cliSecret)
		if err != nil {
			t.Fatalf("load key: %v", err)
		}
		claims, err := token.NewIssuer(key).Verify(strings.TrimSpace(raw))
		if err != nil {
			t.Fatalf("token does not verify: %v", err)
		}
		return claims
	}
	count := func() int {
		t.Helper()
		var n int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
			t.Fatalf("count users: %v", err)
		}
		return n
	}

	// First run: the account does not exist and is created.
	var first bytes.Buffer
	if err := issueToken(ctx, pool, cliSecret, opts, logger, &first); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if got := count(); got != 1 {
		t.Fatalf("users = %d after the first run, want 1", got)
	}
	claims := verify(first.String())
	if claims.Email != "swagger@shop.test" || claims.Name != "swagger" {
		t.Errorf("claims = %+v", claims)
	}
	if got := claims.ExpiresAt.Sub(claims.IssuedAt.Time); got != 24*time.Hour {
		t.Errorf("exp - iat = %v, want 24h", got)
	}
	if strings.Count(first.String(), "\n") != 1 {
		t.Errorf("output %q should be the token and one newline", first.String())
	}

	// Second run: the account exists and is signed in, not duplicated.
	opts.TTL = time.Hour
	var second bytes.Buffer
	if err := issueToken(ctx, pool, cliSecret, opts, logger, &second); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if got := count(); got != 1 {
		t.Errorf("users = %d after the second run, want 1", got)
	}
	again := verify(second.String())
	if again.Subject != claims.Subject {
		t.Errorf("second token is for user %q, first for %q", again.Subject, claims.Subject)
	}
	if got := again.ExpiresAt.Sub(again.IssuedAt.Time); got != time.Hour {
		t.Errorf("exp - iat = %v, want 1h", got)
	}

	// A wrong password for the existing account prints no token.
	opts.Password = otherPassword
	var third bytes.Buffer
	if err := issueToken(ctx, pool, cliSecret, opts, logger, &third); !errors.Is(err, account.ErrInvalidCredentials) {
		t.Errorf("wrong password: err = %v, want ErrInvalidCredentials", err)
	}
	if third.Len() != 0 {
		t.Errorf("a token was printed for a wrong password: %q", third.String())
	}
}

func TestIssueTokenRejectsShortPassword(t *testing.T) {
	pool := testutil.NewPool(t)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	opts := tokenOptions{Email: "swagger@shop.test", TTL: time.Hour, Password: "short"}

	var out bytes.Buffer
	if err := issueToken(context.Background(), pool, cliSecret, opts, logger, &out); err == nil {
		t.Fatal("a 5-character password was accepted")
	}
	if out.Len() != 0 {
		t.Errorf("output = %q, want none", out.String())
	}
}
