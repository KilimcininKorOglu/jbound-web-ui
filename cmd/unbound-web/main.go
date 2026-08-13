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

	"unbound-web/internal/config"
	"unbound-web/internal/database"
	"unbound-web/internal/preflight"
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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := database.Open(ctx, cfg.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()
	slog.Info("database ready", "path", db.Path())

	// Runs for the life of the process. Sessions idle past the timeout and
	// login attempts older than the rate limit window serve no purpose.
	go db.RunCleanupLoop(ctx, cleanupInterval, cfg.SessionTimeout, func(err error) {
		slog.Error("cleanup failed", "error", err)
	})

	handler := web.NewRouter(cfg)

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
