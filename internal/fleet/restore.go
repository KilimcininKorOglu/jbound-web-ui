package fleet

import (
	"bytes"
	"context"
	"errors"
	"time"

	"jbound/internal/audit"
	"jbound/internal/logging"
	"jbound/internal/server"
)

// ErrNoBackup marks a server the panel holds no previous file for.
//
// It is the state of a server nobody has written to yet, so it is an answer
// rather than a fault.
var ErrNoBackup = errors.New("no previous file is stored")

// FileBackup is the host entries file of one server as it was before the panel
// last wrote to it.
type FileBackup struct {
	ServerID int64

	// Content is the file itself, and SHA256 is what the transport reported for
	// it when it was read.
	Content []byte
	SHA256  string

	SavedAt time.Time
}

// BackupStore keeps the last known good file of every server.
type BackupStore interface {
	Save(ctx context.Context, serverID int64, content []byte, digest string, at time.Time) error
	Get(ctx context.Context, serverID int64) (FileBackup, error)
	ServerIDs(ctx context.Context) (map[int64]bool, error)
}

// keepPrevious stores the file a write is about to replace.
//
// A failure is logged and the write carries on. Without this the change went
// through with no copy at all, so refusing it would trade a missing safety net
// for an operator who cannot work, and the copy is only ever read by hand.
func (w *Writer) keepPrevious(ctx context.Context, serverID int64, content []byte, digest string) {
	if err := w.backups.Save(ctx, serverID, content, digest, time.Now()); err != nil {
		logging.From(ctx).Error("cannot keep the previous host entries file",
			"server", serverID, "error", err)
	}
}

// Backups names every server the panel could restore.
func (s *Service) Backups(ctx context.Context) (map[int64]bool, error) {
	return s.writer.backups.ServerIDs(ctx)
}

// RestoreFile puts back the file one server carried before the last write.
func (s *Service) RestoreFile(ctx context.Context, actor server.Actor,
	serverID int64) (ServerResult, error) {

	return s.writer.RestoreFile(ctx, actor, serverID)
}

// RestoreFile writes the stored copy back onto one server.
//
// It travels the same read, keep and write path an ordinary change does, so the
// file it replaces becomes the next copy and a restore can itself be undone.
func (w *Writer) RestoreFile(ctx context.Context, actor server.Actor,
	serverID int64) (ServerResult, error) {

	record, err := w.servers.Get(ctx, serverID)
	if err != nil {
		return ServerResult{}, err
	}
	if refusal, ok := refuse(record); ok {
		return refusal, nil
	}

	backup, err := w.backups.Get(ctx, serverID)
	if err != nil {
		return ServerResult{}, err
	}

	result := ServerResult{ServerID: record.ID, ServerName: record.Name}

	lock := w.lockFor(record.ID)
	lock.Lock()
	defer lock.Unlock()

	client, err := w.pool.Get(w.transportConfig(record))
	if err != nil {
		result.Status = StatusFailed
		result.Message = failureMessage(err)
		return result, nil
	}

	current, digest, err := client.ReadHostEntries(ctx)
	if err != nil {
		result.Status = StatusFailed
		result.Message = failureMessage(err)
		return result, nil
	}

	if bytes.Equal(current, backup.Content) {
		// Writing would change nothing and would replace the copy with an
		// identical one, which costs the operator the file they meant to keep.
		result.Status = StatusSkipped
		result.Message = "The server already holds the stored file"
		return result, nil
	}

	w.keepPrevious(ctx, record.ID, current, digest)

	// No configuration check here, unlike every other write. This is the way
	// out of a bad state, and a check that refused it would take the recovery
	// path away at the moment it is needed. What goes back is what the server
	// held before, so it is a state the resolver already ran with.
	if err := client.WriteHostEntries(ctx, backup.Content, digest); err != nil {
		logging.From(ctx).Error("cannot restore the previous host entries file",
			"server", record.Name, "error", err)

		result.Status = StatusFailed
		result.Message = failureMessage(err)
		return result, nil
	}

	result.Status = StatusSuccess
	result.Message = "The previous file was restored"

	refillCtx, cancelRefill := afterChange(ctx)
	defer cancelRefill()

	if _, refreshErr := w.refresh.oneHeld(refillCtx, record.ID); refreshErr != nil {
		logging.From(ctx).Error("cannot refresh the cache after a restore",
			"server", record.Name, "error", refreshErr)
		result.Message += ", but the cache could not be refreshed"
	}

	w.writeRestoreAudit(ctx, actor, record, backup)
	return result, nil
}

// writeRestoreAudit records what was put back and how old it was.
func (w *Writer) writeRestoreAudit(ctx context.Context, actor server.Actor,
	record server.Server, backup FileBackup) {

	serverID := record.ID
	_ = w.audit.Write(ctx, audit.Entry{
		UID:        actor.UID,
		Username:   actor.Username,
		ServerID:   &serverID,
		ServerName: record.Name,
		Action:     audit.ActionFileRestore,
		Details: "Restored the host entries file of " + record.Name +
			" as it stood on " + backup.SavedAt.Format(time.RFC3339),
		IPAddress: actor.IPAddress,
	})
}
