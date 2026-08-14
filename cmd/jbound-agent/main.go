// Command jbound-agent serves one Unbound resolver to the jbound panel.
//
// It exists to remove the shell. On the ssh path the panel sends command text
// and the target runs it through a login shell, and what keeps that safe is a
// set of exact sudoers rules on every host. Here no command text arrives at
// all: the panel names a step, and the step was decided on this host by
// whoever installed it.
//
// The same holds for files. No request carries a path. The agent writes the
// file its own configuration names, and there is no way to ask it for another,
// which is what keeps a stolen token from becoming permission to write
// /etc/unbound/unbound.conf or an authorized_keys file.
//
// It runs as root, deliberately. Writing the records file and reloading the
// resolver both need it, and running unprivileged with sudoers rules would put
// back the surface this exists to remove. What it gets in exchange is a fixed
// surface: eight authenticated endpoints, no command passing, no shell.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	// shutdownGrace bounds how long an in flight request may finish after a
	// signal. A write that is moving a file into place gets to finish it.
	shutdownGrace = 30 * time.Second

	// readHeaderTimeout is the answer to a caller that opens a connection and
	// says nothing. Without it those accumulate.
	readHeaderTimeout = 10 * time.Second

	// writeTimeout has to clear the longest step. A restart waits for a
	// resolver to come back, and the panel is still holding the request.
	writeTimeout = 5 * time.Minute
)

func main() {
	if err := run(); err != nil {
		slog.Error("the agent did not start", "error", err)
		os.Exit(1)
	}
}

func run() error {
	log := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))
	slog.SetDefault(log)

	cfg, err := Load()
	if err != nil {
		return err
	}

	token, err := readToken(cfg.TokenFile)
	if err != nil {
		return err
	}

	certificate, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
	if err != nil {
		return fmt.Errorf("cannot read the certificate: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	agent := NewAgent(cfg, token, log)

	// Before the first request. A host whose main configuration lost the
	// include line is corrected as the agent comes up rather than the first
	// time somebody happens to make a change.
	agent.ensureIncludeAtStart()

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           agent.Routes(),
		ReadHeaderTimeout: readHeaderTimeout,
		WriteTimeout:      writeTimeout,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		TLSConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{certificate},
		},
	}

	problems := make(chan error, 1)
	go func() {
		log.Info("agent listening",
			"address", cfg.ListenAddr,
			"records", cfg.RecordsPath,
			"main_config", cfg.MainConfig)

		if err := server.ListenAndServeTLS("", ""); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			problems <- err
		}
	}()

	select {
	case err := <-problems:
		return fmt.Errorf("the agent stopped listening: %w", err)
	case <-ctx.Done():
	}

	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("the agent did not shut down cleanly: %w", err)
	}
	return nil
}

// readToken loads the bearer token and refuses a file anyone else can read.
//
// The mode check is not a formality. The token is the whole of the panel's
// authority over this resolver, and a world readable file hands it to every
// account on the host.
func readToken(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("cannot read the token file %s: %w", path, err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return "", fmt.Errorf(
			"the token file %s is mode %o, which lets other accounts read it", path, mode)
	}

	material, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("cannot read the token file %s: %w", path, err)
	}

	// The contents never reach an error message. A token in a log line is a
	// token to rotate.
	token := strings.TrimSpace(string(material))
	if token == "" {
		return "", fmt.Errorf("the token file %s is empty", path)
	}
	return token, nil
}
