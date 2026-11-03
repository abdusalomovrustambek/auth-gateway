# auth-gateway — agent instructions

auth-gateway is the front door of Shop (the demo store for agnts): sign-up and sign-in, JWTs, the JWKS, rate limits, the access log, the web app and the `/api` proxy to shop-api. Read `Implementation plan.md` for the why.

Go 1.23, module `github.com/abdusalomovrustambek/auth-gateway`, Gin, pgx/v5, goose, golang-jwt/v5.

## Layout

```
cmd/auth-gateway/   main.go (config, wiring, server), token.go (the `token` subcommand)
internal/account/   users: register, login, lockout; /auth/* handlers
internal/token/     access JWTs, refresh tokens, signing key, JWKS, bearer middleware
internal/limit/     token-bucket limiters and the Gin middleware
internal/edge/      client IP, access log, reverse proxy, static files
internal/httpx/     JSON errors, request id, client IP on the context
internal/testutil/  test database helper
migrations/         goose SQL, embedded in the binary
```

## Conventions

- Wiring happens only in `cmd/auth-gateway/main.go`. Packages get their dependencies through constructors; handlers stay thin and call services.
- Each package owns its tables and its SQL (hand-written, pgx, parameters only). `account` imports `token`, never the other way round. `limit` takes a key function and does not import `edge`.
- All tables live in schema `auth`. The pool sets `search_path` to it (`migrations.Open`), so SQL uses unqualified table names and goose's version table lands in the same schema. The `auth` role needs no rights outside its schema.
- Errors: wrap with context (`fmt.Errorf("load user: %w", err)`), compare with `errors.Is/As`, do not log an error that is also returned. Client errors are `{"error": "..."}` via `httpx.Error`; 5xx bodies never carry internal detail.
- Logging: access log is the combined format on stdout, one line per request (`internal/edge`). App events use `slog` JSON: `user registered`, `login failed`, `account locked`, `proxy error`. Log the user id; never the password, and not the email either.
- Emails are trimmed and lower-cased before they are stored or looked up.
- Tests: table-driven where cases vary, `t.Helper()` in helpers, no `time.Sleep` to wait for goroutines. Tests that need Postgres call `testutil.NewPool(t)`: it reads `TEST_DATABASE_URL`, makes a throwaway schema, migrates it; the test fails with a clear message when the variable is unset.

## Configuration (environment, `.env` is read if present)

| Variable | Meaning |
|---|---|
| `DATABASE_URL` | required; Postgres, role `auth` |
| `AUTH_KEY_SECRET` | required; encrypts the signing key (AES-256-GCM, key from HKDF-SHA256) |
| `SHOP_API_URL` | required (server); upstream for `/api/*`, the `/api` prefix is kept |
| `ASSETS_DIR` | directory with the web build |
| `TRUSTED_PROXIES` | comma-separated IPs/CIDRs whose `X-Forwarded-For` is trusted |
| `ADDR` | listen address, default `:8080` |
| `GIN_MODE` | Gin mode |
| `AUTH_TOKEN_PASSWORD` | password for the `token` subcommand |
| `TEST_DATABASE_URL` | Postgres for tests (CI sets it) |

Use throwaway values. Never commit `.env`.

## JWT contract with shop-api

- Algorithm `EdDSA` (Ed25519) only. Header `kid` names the key.
- Claims: `sub` (user id), `email`, `name`, `iat`, `exp`, `iss` = `shop.agnts.uz`, `aud` = `shop-api`.
- Access tokens live 15 minutes. Only the `token` subcommand (`auth-gateway token --email ... --ttl 24h`, password from `AUTH_TOKEN_PASSWORD`) makes longer ones.
- Public key: `GET /.well-known/jwks.json` (`kty` OKP, `crv` Ed25519, `kid`, `use` sig, `alg` EdDSA). shop-api verifies; the gateway does not authorize `/api`.
- Refresh token: 32 random bytes, base64url, stored as SHA-256, 30 days, rotated on use. Cookie `HttpOnly; Secure; SameSite=Strict; Path=/auth` (a Secure cookie is not sent over plain http, so manual testing needs https or a browser that allows localhost).

## Checks

`go build ./... && go vet ./... && go test -race ./...` (with `TEST_DATABASE_URL` set), `golangci-lint run`, `docker build .`.
