// Command unbound-web runs the multi server Unbound management panel.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"unbound-web/internal/audit"
	"unbound-web/internal/auth"
	"unbound-web/internal/config"
	"unbound-web/internal/database"
	"unbound-web/internal/dnsquery"
	"unbound-web/internal/fleet"
	"unbound-web/internal/preflight"
	"unbound-web/internal/server"
	"unbound-web/internal/settings"
	"unbound-web/internal/siem"
	"unbound-web/internal/store"
	"unbound-web/internal/transport"
	"unbound-web/internal/web"
)

const (
	// shutdownGrace bounds how long in flight requests may finish after a
	// signal.
	shutdownGrace = 15 * time.Second

	// cleanupInterval controls how often expired sessions and stale login
	// attempts are removed.
	cleanupInterval = 10 * time.Minute
)

func main() {
	if err := run(); err != nil {
		slog.Error("startup failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	if err := preflight.NotRoot(); err != nil {
		return err
	}
	if err := preflight.DataDir(cfg.DataDir, cfg.KeyDir); err != nil {
		return err
	}
	// Authentication is impossible without the helper, so the panel refuses to
	// start rather than serving a login form that can only fail.
	if err := preflight.AuthHelper(cfg.AuthHelperPath); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := database.Open(ctx, cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()
	slog.Info("database ready", "path", db.Path())

	// The settings the operator can change without a restart. Everything the
	// panel reads through an accessor below comes from here.
	options := settings.NewService(store.NewSettings(db.DB))
	if err := options.Load(ctx); err != nil {
		return err
	}

	// Runs for the life of the process. Sessions idle past the timeout and
	// login attempts older than the rate limit window serve no purpose.
	go db.RunCleanupLoop(ctx, cleanupInterval,
		options.DurationOf(settings.SessionIdleTimeout),
		options.DurationOf(settings.LoginRateWindow),
		func(err error) {
			slog.Error("cleanup failed", "error", err)
		})

	authenticator, err := auth.NewHelperAuthenticator(cfg.AuthHelperPath, cfg.AuthMaxConcurrent)
	if err != nil {
		return err
	}
	authService := auth.NewService(authenticator, auth.Policy{
		MinUID:       cfg.MinUID,
		AdminGroup:   cfg.AdminGroup,
		AllowedGroup: cfg.AllowedGroup,
	})
	sessions := auth.NewSessionManager(store.NewSessions(db.DB),
		options.DurationOf(settings.SessionIdleTimeout),
		options.DurationOf(settings.SessionLifetime), cfg.CookieSecure)
	limiter := auth.NewRateLimiter(store.NewLoginAttempts(db.DB),
		options.DurationOf(settings.LoginRateWindow),
		options.IntOf(settings.LoginRateMaxAttempts))
	// The panel host name travels with every forwarded event, so a receiver
	// collecting several panels can tell them apart.
	panelHost, err := os.Hostname()
	if err != nil {
		return fmt.Errorf("cannot read the host name: %w", err)
	}
	forwarder := siem.NewForwarder(panelHost)
	defer forwarder.Close()

	auditLog := audit.NewLogger(store.NewAuditLogs(db.DB), forwarder).
		WithForwarding(options.BoolOf(settings.SIEMForwardingEnabled))

	keys, err := server.NewKeyStore(cfg.DataDir)
	if err != nil {
		return err
	}
	// The pool closes with the process, which is what releases every SSH
	// connection on shutdown.
	pool := transport.NewPool(ctx, options.DurationOf(settings.SSHIdleTimeout))
	defer pool.Close()

	timeouts := func() server.Timeouts {
		return server.Timeouts{
			Connect: options.Duration(settings.SSHConnectTimeout),
			Command: options.Duration(settings.SSHCommandTimeout),
		}
	}
	servers := store.NewServers(db.DB)

	serverService := server.NewService(
		servers, store.NewGroups(db.DB), keys, pool, auditLog, cfg.DataDir, timeouts)

	records := store.NewRecords(db.DB)
	states := store.NewStates(db.DB)

	// The first pass runs as soon as the panel is up, so the first page load
	// reads a filled cache instead of waiting for the interval.
	concurrent := options.IntOf(settings.FleetMaxConcurrent)
	refresher := fleet.NewRefresher(servers, records, states,
		pool, cfg.DataDir, timeouts, concurrent)
	refresher.Start(ctx, options.DurationOf(settings.CacheRefreshInterval))

	writer := fleet.NewWriter(servers, serverService, pool, refresher, auditLog,
		cfg.DataDir, timeouts, concurrent)
	queries := dnsquery.New(cfg.DigPath, options.DurationOf(settings.DNSQueryTimeout))
	recordService := fleet.NewService(records, states, writer, refresher,
		queries, auditLog, options.DurationOf(settings.CacheStaleAfter))

	rsyslog := siem.NewManager(cfg.RsyslogConfPath, cfg.SyslogLogPath,
		cfg.RsyslogValidateCmd, cfg.RsyslogRestartCmd, cfg.RsyslogStatusCmd)

	app, err := web.NewApp(web.Deps{
		Config:    cfg,
		Settings:  options,
		Auth:      authService,
		Sessions:  sessions,
		Limiter:   limiter,
		Audit:     auditLog,
		Servers:   serverService,
		Records:   recordService,
		SIEM:      rsyslog,
		Forwarder: forwarder,
		Hostname:  panelHost,
		Started:   time.Now(),
	})
	if err != nil {
		return err
	}
	handler := app.Router()

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		slog.Info("panel listening",
			"addr", cfg.ListenAddr,
			"data_dir", cfg.DataDir,
			"pam_service", cfg.PAMService,
			"uid", os.Geteuid(),
		)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	select {
	case err := <-serverErr:
		if err != nil {
			return fmt.Errorf("http server failed: %w", err)
		}
		return nil
	case <-ctx.Done():
		slog.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown failed: %w", err)
	}
	slog.Info("shutdown complete")
	return nil
}
