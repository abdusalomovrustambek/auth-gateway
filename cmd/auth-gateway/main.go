// Command auth-gateway is the front door of Shop: sign-in and JWTs, rate limits,
// the access log, the web app and the /api proxy to shop-api.
//
//	auth-gateway                       run the server
//	auth-gateway token --email ...     print an access token (see token.go)
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"

	"github.com/abdusalomovrustambek/auth-gateway/internal/account"
	"github.com/abdusalomovrustambek/auth-gateway/internal/edge"
	"github.com/abdusalomovrustambek/auth-gateway/internal/httpx"
	"github.com/abdusalomovrustambek/auth-gateway/internal/limit"
	"github.com/abdusalomovrustambek/auth-gateway/internal/token"
	"github.com/abdusalomovrustambek/auth-gateway/migrations"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "auth-gateway:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if err := godotenv.Load(); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("read .env: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if len(args) == 0 {
		return serve(ctx, os.Getenv)
	}
	switch args[0] {
	case "token":
		return runToken(ctx, args[1:], os.Getenv, os.Stdout)
	default:
		return fmt.Errorf("unknown command %q (use no command to run the server, or `token`)", args[0])
	}
}

// config is the environment of the service.
type config struct {
	DatabaseURL    string
	KeySecret      string
	ShopAPIURL     string
	AssetsDir      string
	TrustedProxies string
	Addr           string
}

// loadConfig reads the configuration. The server needs SHOP_API_URL; the token
// command does not. Missing required values are all named in the error.
func loadConfig(getenv func(string) string, server bool) (config, error) {
	cfg := config{
		DatabaseURL:    getenv("DATABASE_URL"),
		KeySecret:      getenv("AUTH_KEY_SECRET"),
		ShopAPIURL:     getenv("SHOP_API_URL"),
		AssetsDir:      getenv("ASSETS_DIR"),
		TrustedProxies: getenv("TRUSTED_PROXIES"),
		Addr:           getenv("ADDR"),
	}
	required := []struct{ name, value string }{
		{"DATABASE_URL", cfg.DatabaseURL},
		{"AUTH_KEY_SECRET", cfg.KeySecret},
	}
	if server {
		required = append(required, struct{ name, value string }{"SHOP_API_URL", cfg.ShopAPIURL})
	}
	var missing []string
	for _, r := range required {
		if strings.TrimSpace(r.value) == "" {
			missing = append(missing, r.name)
		}
	}
	if len(missing) > 0 {
		return config{}, fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}
	if cfg.AssetsDir == "" {
		cfg.AssetsDir = "."
	}
	if cfg.Addr == "" {
		cfg.Addr = ":8080"
	}
	return cfg, nil
}

// prepare runs the migrations and loads (or makes) the signing key. The server
// and the token command start the same way.
func prepare(ctx context.Context, pool *pgxpool.Pool, keySecret string) (*token.Key, error) {
	if err := migrations.Up(ctx, pool); err != nil {
		return nil, err
	}
	return token.LoadOrCreateKey(ctx, pool, keySecret)
}

func serve(ctx context.Context, getenv func(string) string) error {
	cfg, err := loadConfig(getenv, true)
	if err != nil {
		return err
	}
	target, err := parseUpstream(cfg.ShopAPIURL)
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	pool, err := migrations.Open(ctx, cfg.DatabaseURL, migrations.Schema)
	if err != nil {
		return err
	}
	defer pool.Close()
	key, err := prepare(ctx, pool, cfg.KeySecret)
	if err != nil {
		return err
	}

	router, err := newRouter(routerDeps{
		cfg: cfg, pool: pool, key: key, upstream: target, log: logger, accessLog: os.Stdout,
	})
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	logger.Info("listening", "addr", cfg.Addr)

	select {
	case err := <-errCh:
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}

func parseUpstream(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("SHOP_API_URL: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("SHOP_API_URL %q must be an http(s) URL with a host", raw)
	}
	return u, nil
}

type routerDeps struct {
	cfg       config
	pool      *pgxpool.Pool
	key       *token.Key
	upstream  *url.URL
	log       *slog.Logger
	accessLog io.Writer
}

// newRouter wires the middleware, the limits and the routes.
func newRouter(d routerDeps) (*gin.Engine, error) {
	store := account.NewStore(d.pool)
	svc, err := account.NewService(store, d.log)
	if err != nil {
		return nil, err
	}
	issuer := token.NewIssuer(d.key)
	auth := account.NewHandler(svc, issuer, token.NewRefresh(d.pool), d.log)

	clientKey := func(c *gin.Context) string { return httpx.ClientIP(c) }
	loginLimit := limit.Middleware(limit.Per(10, time.Minute), clientKey)
	registerLimit := limit.Middleware(limit.Per(5, time.Hour), clientKey)
	globalLimit := limit.Middleware(limit.Per(50, time.Second), clientKey)

	r := gin.Default()
	r.Use(
		httpx.RequestID(),
		edge.ClientIP(edge.ParseTrusted(d.cfg.TrustedProxies)),
		edge.AccessLog(d.accessLog),
		limit.OnPath("/auth/login", loginLimit),
		limit.OnPath("/auth/register", registerLimit),
		globalLimit,
	)

	auth.Routes(r)
	r.GET("/.well-known/jwks.json", token.JWKS(d.key))
	r.GET("/healthz", healthz(d.pool))
	r.Any("/api/*path", edge.Proxy(d.upstream, d.log))
	r.NoRoute(edge.Static(d.cfg.AssetsDir))
	return r, nil
}

// healthz pings the database and answers 503 when it does not answer.
func healthz(pool *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		defer cancel()
		if err := pool.Ping(ctx); err != nil {
			slog.Error("healthz: database ping failed", "error", err)
			httpx.Error(c, http.StatusServiceUnavailable, "database unavailable")
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}
}
