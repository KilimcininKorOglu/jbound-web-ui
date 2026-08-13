package fleet

import (
	"context"
	"strings"

	"unbound-web/internal/audit"
	"unbound-web/internal/server"
)

// maxReloadOutput bounds how much of a reload's output reaches the audit row.
// A resolver that fails loudly can produce pages of it, and an audit row is
// meant to be read rather than scrolled.
const maxReloadOutput = 400

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

	client, err := w.pool.Get(record.TransportConfig(
		w.dataDir, w.timeouts.Connect, w.timeouts.Command))
	if err != nil {
		result.Status = StatusFailed
		result.Message = err.Error()
		return result
	}

	output, err := client.Reload(ctx)
	if err != nil {
		result.Status = StatusFailed
		result.Message = err.Error()
		return result
	}

	result.Status = StatusSuccess
	result.Message = "Resolver reloaded"

	// What the resolver just read is the file as it stands now, so that digest
	// becomes the applied one and the unapplied marker clears. A read that
	// fails leaves the marker up, which is the safe direction: the operator
	// sees work still to do rather than a change that never went live.
	if err := w.recordApplied(ctx, record.ID); err != nil {
		result.Message = "Resolver reloaded, but the panel could not confirm the file"
	}

	w.writeReloadAudit(ctx, actor, record, output, groupName)
	return result
}

// recordApplied reads the server again and stores the digest it now holds.
func (w *Writer) recordApplied(ctx context.Context, serverID int64) error {
	result, err := w.refresh.One(ctx, serverID)
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
	record server.Server, output, groupName string) {

	details := "Unbound service reloaded. Output: " + reloadOutput(output)
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
	folded := strings.Join(strings.Fields(output), " ")
	if folded == "" {
		return "none"
	}
	if len(folded) > maxReloadOutput {
		return folded[:maxReloadOutput] + "..."
	}
	return folded
}
