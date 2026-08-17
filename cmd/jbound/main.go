// Command jbound runs the multi server Unbound management panel.
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

	"jbound/internal/audit"
	"jbound/internal/auth"
	"jbound/internal/config"
	"jbound/internal/database"
	"jbound/internal/dnsquery"
	"jbound/internal/fleet"
	"jbound/internal/logging"
	"jbound/internal/preflight"
	"jbound/internal/server"
	"jbound/internal/settings"
	"jbound/internal/siem"
	"jbound/internal/store"
	"jbound/internal/transport"
	"jbound/internal/web"
)

const (
	// shutdownGrace bounds how long in flight requests may finish after a
	// signal.
	shutdownGrace = 15 * time.Second

	// cleanupInterval controls how often expired sessions and stale login
	// attempts are removed.
	cleanupInterval = 10 * time.Minute

	// httpWriteTimeout is the last resort against a client that stops reading.
	// It has to stay above the largest fleet_operation_timeout an operator can
	// configure, or a long operation loses its report to the transport again.
	// A test holds the two together.
	httpWriteTimeout = 15 * time.Minute
)

// usage is printed for an argument the command does not know.
const usage = `jbound manages several Unbound resolvers, over SSH or through an agent.

  jbound                        run the panel
  jbound backup <dir>           write a consistent copy of the data directory
  jbound import-audit <file>    read the audit trail of an older installation
`

func main() {
	if err := dispatch(os.Args[1:]); err != nil {
		slog.Error("startup failed", "error", err)
		os.Exit(1)
	}
}

// dispatch picks what the process does.
//
// No arguments keeps the behaviour the systemd unit relies on, so an upgrade
// changes nothing about how the panel is started.
func dispatch(args []string) error {
	if len(args) == 0 {
		return run()
	}

	switch args[0] {
	case "backup":
		if len(args) != 2 {
			return fmt.Errorf("backup needs one target directory")
		}
		return runBackup(args[1])
	case "import-audit":
		if len(args) != 2 {
			return fmt.Errorf("import-audit needs one file to read")
		}
		return runImportAudit(args[1])
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
		return nil
	}
}

// watchLogLevel switches to debug and back on SIGUSR1.
//
// An operator raising the level during an incident keeps the SSH pool, the
// cache and the requests being diagnosed. Restarting to change the level
// would take away the state that was being looked at.
func watchLogLevel(ctx context.Context, configured slog.Level) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGUSR1)
	defer signal.Stop(signals)

	toggleLogLevel(ctx, signals, configured)
}

// toggleLogLevel switches between the configured level and debug, one switch
// per signal, so the same lever turns the detail back off again.
func toggleLogLevel(ctx context.Context, signals <-chan os.Signal,
	configured slog.Level) {

	debugging := false
	for {
		select {
		case <-ctx.Done():
			return
		case <-signals:
			debugging = !debugging
			level := configured
			if debugging {
				level = slog.LevelDebug
			}
			logging.SetLevel(level)
			slog.Info("log level changed", "level", level.String())
		}
	}
}

func run() error {
	// The handler reads the level on every record, so the configured value
	// below and the SIGUSR1 switch both take effect without a restart. The
	// logger is in place before the configuration is read, because a
	// configuration that cannot be read is the first thing worth logging.
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: logging.Level(),
	}))
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	logging.SetLevel(cfg.LogLevel)

	preflight.WarnIfRoot("the panel holds an SSH key to every managed server, " +
		"so one flaw in the HTTP layer would hand over the whole fleet")

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

	go watchLogLevel(ctx, cfg.LogLevel)

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

	// The receiver the panel talks to itself. It needs no daemon on the host and
	// no privilege, and a receiver that is down costs a growing backlog rather
	// than lost events, because the queue reads the trail out of the database.
	sender := siem.NewSender(panelHost,
		options.StringOf(settings.SIEMProtocol),
		options.StringOf(settings.SIEMReceiverHost),
		options.IntOf(settings.SIEMReceiverPort))
	defer sender.Close()

	auditLogs := store.NewAuditLogs(db.DB)
	queue := siem.NewQueue(auditLogs, store.NewSIEMCursor(db.DB), sender, panelHost,
		options.BoolOf(settings.SIEMForwardingEnabled))
	go queue.RunLoop(ctx)

	auditLog := audit.NewLogger(auditLogs, forwarder).
		WithForwarding(options.BoolOf(settings.SIEMForwardingEnabled)).
		WithNotify(queue.Notify)

	keys, err := server.NewKeyStore(cfg.DataDir)
	if err != nil {
		return err
	}
	// The deferred close runs after the HTTP server has drained, so a fleet
	// operation that started before the signal can still reach its servers
	// during the shutdown grace.
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
		store.NewBackups(db.DB), cfg.DataDir, timeouts, concurrent)
	queries := dnsquery.New(cfg.DigPath, options.DurationOf(settings.DNSQueryTimeout))
	recordService := fleet.NewService(records, states, writer, refresher,
		queries, auditLog, options.DurationOf(settings.CacheStaleAfter),
		options.IntOf(settings.RecordsPerPage))

	rsyslog := siem.NewManager(cfg.SIEMRulesPath, cfg.SyslogLogPath,
		cfg.RsyslogApplyCmd, cfg.RsyslogRestartCmd, cfg.RsyslogStatusCmd)

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
		Receiver:  sender,
		Backlog:   queue,
		Health:    db.Probe,
		Hostname:  panelHost,
		Started:   time.Now(),
	})
	if err != nil {
		return err
	}
	handler := app.Router()

	server := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: handler,
		// Whatever net/http reports for itself, a bad TLS record or a panic it
		// recovered, joins the structured stream instead of landing on stderr
		// in another format.
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelError),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// A transport deadline, not a handler one: it cancels nothing and
		// produces no status, so a fleet operation that outlives it loses the
		// per-server report the operator needs. The panel bounds those
		// handlers itself with fleet_operation_timeout, and this stays above
		// its maximum so the report always lands.
		WriteTimeout: httpWriteTimeout,
		IdleTimeout:  120 * time.Second,
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
