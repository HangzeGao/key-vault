// Command key-vault runs the engineering baseline key-vault service.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kvlt/key-vault/internal/api/admin"
	"github.com/kvlt/key-vault/internal/api/baselineapi"
	cryptoapi "github.com/kvlt/key-vault/internal/api/crypto"
	keytransferapi "github.com/kvlt/key-vault/internal/api/keytransfer"
	"github.com/kvlt/key-vault/internal/api/ops"
	"github.com/kvlt/key-vault/internal/api/server"
	"github.com/kvlt/key-vault/internal/bootstrap"
	"github.com/kvlt/key-vault/internal/config"
	"github.com/kvlt/key-vault/internal/logging"
)

func main() {
	cfgPath := flag.String("config", "", "path to YAML config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		slog.Error("config load failed", "error", err)
		os.Exit(1)
	}

	level := slog.LevelInfo
	switch cfg.LogLevel {
	case "DEBUG":
		level = slog.LevelDebug
	case "WARN":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	}
	logger := logging.New(level)
	slog.SetDefault(logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	app, err := bootstrap.Build(ctx, cfg)
	if err != nil {
		slog.Error("bootstrap failed", "error", err)
		os.Exit(1)
	}
	defer app.Store.Close()

	// Lifecycle mutation is owned by the management plane. Data and Ops
	// processes keep the dependency available for read-only diagnostics but do
	// not run duplicate schedulers.
	workerStarted := cfg.Server.ActivePlane == "management" || cfg.Server.ActivePlane == "all"
	if workerStarted {
		app.Worker.Start(ctx)
		defer app.Worker.Stop()
	}

	adminH := admin.New(app.KeyService)
	cryptoH := cryptoapi.New(app.CryptoService)
	keyTransferH := keytransferapi.New(app.KeyTransferService)
	baselineH := baselineapi.New(app.AuditChain, app.PolicyMgr, app.Worker, app.CryptoService, app.Resolver, app.Store, cfg)
	opsH := ops.New(ops.Deps{
		Store:      app.Store,
		Resolver:   app.Resolver,
		AuditChain: app.AuditChain,
		PolicyMgr:  app.PolicyMgr,
		Worker:     app.Worker,
		Cfg:        cfg,
	})

	srv, err := server.New(server.Deps{
		Cfg:                cfg,
		AdminHandler:       adminH,
		CryptoHandler:      cryptoH,
		BaselineHandler:    baselineH,
		OpsHandler:         opsH,
		TenantHandler:      app.TenantHandler,
		KeyTransferHandler: keyTransferH,
		JWTVerifier:        app.JWTVerifier,
		HMACVerifier:       app.HMACVerifier,
		StaticTokens:       app.StaticTokens,
	})
	if err != nil {
		slog.Error("server initialization failed", "error", err)
		os.Exit(1)
	}

	// Signal handling.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		slog.Info("shutting down")
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutCancel()
		_ = srv.Shutdown(shutCtx)
		cancel()
	}()

	listenAddr := cfg.Server.HTTPListenAddr
	if cfg.Server.TLSCertFile != "" {
		listenAddr = cfg.Server.HTTPSListenAddr
	}
	slog.Info("key-vault starting", "addr", listenAddr, "plane", cfg.Server.ActivePlane, "tls", cfg.Server.TLSCertFile != "")
	if err := srv.Start(); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
