// Command shield runs Sentinel Shield: an MCP gateway + step-level policy
// engine for AI agents.
//
//	shield -config configs/shield.yaml            # run the gateway
//	shield -config configs/shield.yaml -mint \
//	   -agent customer-support-bot -sub alice -scope "db:read crm:update"   # dev token
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/your-org/sentinel/shield/internal/gateway"
	"github.com/your-org/sentinel/shield/internal/guard"
	"github.com/your-org/sentinel/shield/internal/hitl"
	"github.com/your-org/sentinel/shield/internal/identity"
	"github.com/your-org/sentinel/shield/internal/policy"
	"github.com/your-org/sentinel/shield/internal/telemetry"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen      string             `yaml:"listen"`
	AdminListen string             `yaml:"admin_listen"`
	AdminToken  string             `yaml:"admin_token"`
	PolicyFile  string             `yaml:"policy_file"`
	Strict      bool               `yaml:"strict_headers"`
	Separator   string             `yaml:"tool_separator"`
	Auth        AuthConfig         `yaml:"auth"`
	Backends    []*gateway.Backend `yaml:"backends"`
}

type AuthConfig struct {
	Secret   string `yaml:"hs256_secret"`
	Issuer   string `yaml:"issuer"`
	Audience string `yaml:"audience"`
}

func main() {
	cfgPath := flag.String("config", "configs/shield.yaml", "path to shield.yaml")
	mint := flag.Bool("mint", false, "print a dev agent token and exit")
	agent := flag.String("agent", "customer-support-bot", "agent id for -mint")
	sub := flag.String("sub", "alice@example.com", "human subject for -mint")
	scope := flag.String("scope", "db:read", "space-separated scopes for -mint")
	sid := flag.String("sid", "", "session id for -mint (random if empty)")
	ttl := flag.Duration("ttl", 10*time.Minute, "token lifetime for -mint")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}

	if *mint {
		if *sid == "" {
			*sid = fmt.Sprintf("sess_%d", time.Now().UnixNano())
		}
		tok, err := identity.SignHS256([]byte(cfg.Auth.Secret), map[string]any{
			"iss": cfg.Auth.Issuer, "aud": cfg.Auth.Audience, "sub": *sub,
			"act": map[string]any{"sub": *agent}, "sid": *sid, "scope": *scope,
			"iat": time.Now().Unix(), "exp": time.Now().Add(*ttl).Unix(),
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println(tok)
		return
	}

	pol, err := policy.LoadFile(cfg.PolicyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	approvals := hitl.NewStore(15 * time.Minute)
	engine := policy.NewEngine(pol, approvals)
	revocations := identity.NewMemoryRevocations()
	verifier := &identity.HS256Verifier{Secret: []byte(cfg.Auth.Secret), Issuer: cfg.Auth.Issuer,
		Audience: cfg.Auth.Audience, Revocations: revocations, Leeway: 30 * time.Second}
	rec := telemetry.SlogRecorder{L: log}

	gw := gateway.New(gateway.Options{Backends: cfg.Backends, StrictHeaders: cfg.Strict, ToolSeparator: cfg.Separator},
		engine, verifier, rec, guard.NewMemoryPins())

	mux := http.NewServeMux()
	mux.Handle("/mcp", gw)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	srv := &http.Server{Addr: cfg.Listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	admin := &http.Server{Addr: cfg.AdminListen, Handler: gw.AdminHandler(cfg.AdminToken, revocations), ReadHeaderTimeout: 10 * time.Second}

	// Hot reload policy on SIGHUP.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if p, err := policy.LoadFile(cfg.PolicyFile); err != nil {
				log.Error("policy reload failed; keeping previous policy", "err", err)
			} else {
				engine.Swap(p)
				log.Info("policy reloaded")
			}
		}
	}()

	go func() {
		log.Info("admin listening", "addr", cfg.AdminListen)
		if err := admin.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("admin server", "err", err)
		}
	}()
	go func() {
		log.Info("sentinel shield listening", "addr", cfg.Listen, "backends", len(cfg.Backends))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server", "err", err)
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	_ = admin.Shutdown(ctx)
}

func loadConfig(p string) (*Config, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal([]byte(os.ExpandEnv(string(b))), &c); err != nil {
		return nil, err
	}
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.AdminListen == "" {
		c.AdminListen = "127.0.0.1:8081"
	}
	if len(c.Auth.Secret) < 32 {
		return nil, errors.New("auth.hs256_secret must be at least 32 bytes")
	}
	if len(c.Backends) == 0 {
		return nil, errors.New("at least one backend is required")
	}
	return &c, nil
}
