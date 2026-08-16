package fleet

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"jbound/internal/audit"
	"jbound/internal/logging"
	"jbound/internal/server"
	"jbound/internal/transport"
)

// maxReloadOutput bounds how much of a reload's output reaches the audit row.
// A resolver that fails loudly can produce pages of it, and an audit row is
// meant to be read rather than scrolled.
const maxReloadOutput = 400

// How long a restarted resolver is given to come back, and how often it is
// asked. A restart has to start a process, so unlike a reload it is not
// finished when the command that asked for it returns.
const (
	restartAttempts = 15
	restartWait     = 2 * time.Second
)

// Reload failures the operator can act on.
var (
	// ErrResolverDown marks a step that ran and left the resolver stopped,
	// which is what a configuration Unbound accepts at start but not on SIGHUP
	// does to it.
	ErrResolverDown = errors.New("the resolver is not running")

	// ErrNoReloadStep marks a server record that names no reload command at
	// all, so there was nothing to run.
	ErrNoReloadStep = errors.New("the server names no reload command")
)

// Reload asks the resolver on every server of the target to re-read its files.
//
// Writing the file changes what the server holds. Until the resolver reloads,
// it still answers from what it read at start, so the two steps stay separate
// and the operator decides when the change goes live.
func (w *Writer) Reload(ctx context.Context, actor server.Actor, target Target) (Report, error) {
	targets, groupName, err := w.Targets(ctx, target)
	if err != nil {
		return Report{}, err
	}

	results := w.fanOut(ctx, targets, func(ctx context.Context, record server.Server) ServerResult {
		return w.reloadOne(ctx, actor, record, groupName)
	})

	return Report{Results: results, GroupName: groupName}, nil
}

// reloadOne reloads the resolver of one server.
func (w *Writer) reloadOne(ctx context.Context, actor server.Actor,
	record server.Server, groupName string) ServerResult {

	if refusal, ok := refuse(record); ok {
		return refusal
	}
	result := ServerResult{ServerID: record.ID, ServerName: record.Name}

	// The same lock a write takes. A reload halfway through a write would load
	// whichever of the two files happened to be in place.
	lock := w.lockFor(record.ID)
	lock.Lock()
	defer lock.Unlock()

	client, err := w.pool.Get(w.transportConfig(record))
	if err != nil {
		result.fail(err)
		return result
	}

	step, output, err := w.climb(ctx, client, record)
	if err != nil {
		result.fail(err)

		// No audit row and no applied digest. The trail records what the
		// resolver took, and it took nothing; the operator sees work still to
		// do, which is the truth: the file is on the server and the resolver
		// is not serving it.
		return result
	}

	result.Status = StatusSuccess
	result.Message = step.message

	// What the resolver just read is the file as it stands now, so that digest
	// becomes the applied one and the unapplied marker clears. A read that
	// fails leaves the marker up, which is the safe direction: the operator
	// sees work still to do rather than a change that never went live.
	if err := w.recordApplied(ctx, record.ID); err != nil {
		result.Message = step.message + ", but the panel could not confirm the file"
	}

	w.writeReloadAudit(ctx, actor, record, step, output, groupName)
	return result
}

// rung is one step of the reload ladder.
type rung struct {
	// name reaches the audit row, so a reader knows which of the three ran.
	name string

	// message is what the result table says when this rung is the one that
	// worked, because "reloaded" and "restarted" are not the same news.
	message string

	// run is the transport call. It answers ErrStepSkipped when the server
	// record names no command for this rung.
	run func(context.Context, transport.Transport) (string, error)

	// waits marks a rung that has to start a process rather than signal one,
	// so the resolver is given time to come back rather than asked once.
	waits bool
}

// The ladder, in the order it is climbed. The first rung preserves the cache,
// so it is the one an operator wants to succeed.
var ladder = []rung{
	{
		name: "reload", message: "Resolver reloaded",
		run: func(ctx context.Context, c transport.Transport) (string, error) {
			return c.Reload(ctx)
		},
	},
	{
		name: "reload fallback", message: "Resolver reloaded through the fallback",
		run: func(ctx context.Context, c transport.Transport) (string, error) {
			return c.ReloadFallback(ctx)
		},
	},
	{
		name: "restart", message: "Resolver restarted",
		run: func(ctx context.Context, c transport.Transport) (string, error) {
			return c.Restart(ctx)
		},
		waits: true,
	},
}

// climb runs the rungs in order until the resolver is running again.
//
// A rung that fails is not the end of it, and neither is a rung that succeeds:
// a configuration Unbound accepted at start but not on SIGHUP stops the daemon,
// and the command that sent the signal exits zero. Proving the resolver is up
// is what makes the report worth reading.
func (w *Writer) climb(ctx context.Context, client transport.Transport,
	record server.Server) (rung, string, error) {

	var lastErr error
	var lastRung rung
	var lastOutput string

	for _, step := range ladder {
		output, err := step.run(ctx, client)
		switch {
		case errors.Is(err, transport.ErrStepSkipped):
			// The server record names no command for this rung.
			continue
		case err != nil:
			logging.From(ctx).Warn("a reload step failed",
				"server", record.Name, "step", step.name, "error", err)

			lastErr, lastRung, lastOutput = err, step, output
			continue
		}

		active, detail, statusErr := w.settled(ctx, client, step)
		if statusErr != nil {
			lastErr, lastRung, lastOutput = statusErr, step, output
			continue
		}
		if !active {
			logging.From(ctx).Warn("a reload step left the resolver stopped",
				"server", record.Name, "step", step.name, "status", detail)

			lastErr = fmt.Errorf("%w: the resolver is not running after the %s",
				ErrResolverDown, step.name)
			lastRung, lastOutput = step, output
			continue
		}
		return step, output, nil
	}

	if lastErr == nil {
		// Every rung was skipped, so the server record names no command at all.
		return rung{name: "none"}, "", ErrNoReloadStep
	}
	return lastRung, lastOutput, lastErr
}

// settled reports whether the resolver is running, waiting for it when the rung
// that ran had to start one.
func (w *Writer) settled(ctx context.Context, client transport.Transport,
	step rung) (bool, string, error) {

	var budget time.Duration
	if step.waits {
		budget = w.restartSettle
	}
	deadline := time.Now().Add(budget)

	for {
		active, detail, err := client.ServiceStatus(ctx)
		if err != nil {
			return false, detail, err
		}
		if active || !time.Now().Before(deadline) {
			return active, detail, nil
		}

		select {
		case <-ctx.Done():
			return false, detail, ctx.Err()
		case <-time.After(restartWait):
		}
	}
}

// recordApplied reads the server again and stores the digest it now holds.
//
// The caller holds the lock of this server, so the read goes through the held
// entry point rather than taking it a second time.
func (w *Writer) recordApplied(ctx context.Context, serverID int64) error {
	// The resolver has already reloaded, so this read outlives the request the
	// way the reload itself does.
	ctx, cancel := afterChange(ctx)
	defer cancel()

	result, err := w.refresh.oneHeld(ctx, serverID)
	if err != nil {
		return err
	}
	if result.Err != nil {
		return result.Err
	}
	return w.refresh.markApplied(ctx, serverID, result.Digest)
}

// writeReloadAudit records one server's reload.
func (w *Writer) writeReloadAudit(ctx context.Context, actor server.Actor,
	record server.Server, step rung, output, groupName string) {

	// Which rung ran is the useful part. A fleet whose first rung always
	// fails is dropping its cache on every change, and the trail is where
	// that shows.
	details := fmt.Sprintf("Unbound service reloaded through the %s. Output: %s",
		step.name, reloadOutput(output))
	if groupName != "" {
		details += " (group " + groupName + ")"
	}

	serverID := record.ID
	_ = w.audit.Write(ctx, audit.Entry{
		UID:        actor.UID,
		Username:   actor.Username,
		ServerID:   &serverID,
		ServerName: record.Name,
		Action:     audit.ActionDNSRestart,
		Details:    details,
		IPAddress:  actor.IPAddress,
	})
}

// reloadOutput folds a command's output into one readable line.
func reloadOutput(output string) string {
	return foldOutput(output, maxReloadOutput)
}

// foldOutput folds a remote command's output into one readable line and bounds
// its length. A resolver that fails loudly can produce pages of it, and the
// places this reaches are meant to be read rather than scrolled.
func foldOutput(output string, limit int) string {
	folded := strings.Join(strings.Fields(output), " ")
	if folded == "" {
		return "none"
	}
	if len(folded) > limit {
		return folded[:limit] + "..."
	}
	return folded
}
