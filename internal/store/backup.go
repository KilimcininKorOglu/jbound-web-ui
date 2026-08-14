package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"jbound/internal/fleet"
)

// Backups holds the records file of each server as it was before the
// panel last wrote it.
type Backups struct {
	db *sql.DB
}

// NewBackups builds the file backup store.
func NewBackups(db *sql.DB) *Backups { return &Backups{db: db} }

// Save records the copy of one server, replacing the one before it.
//
// One row per server. The copy that matters is the file as it was before the
// change the operator is about to regret, and every older one is a change they
// have already lived with.
func (b *Backups) Save(ctx context.Context, serverID int64, content []byte,
	digest string, at time.Time) error {

	const query = `
INSERT INTO file_backups (server_id, content, sha256, saved_at)
VALUES (?, ?, ?, ?)
ON CONFLICT (server_id) DO UPDATE SET
    content  = excluded.content,
    sha256   = excluded.sha256,
    saved_at = excluded.saved_at`

	_, err := b.db.ExecContext(ctx, query, serverID, string(content), digest,
		formatTime(at))
	if err != nil {
		return fmt.Errorf("cannot store the previous file of server %d: %w", serverID, err)
	}
	return nil
}

// Get reads the copy of one server.
func (b *Backups) Get(ctx context.Context, serverID int64) (fleet.FileBackup, error) {
	row := b.db.QueryRowContext(ctx,
		"SELECT content, sha256, saved_at FROM file_backups WHERE server_id = ?", serverID)

	var (
		content string
		digest  string
		saved   string
	)
	switch err := row.Scan(&content, &digest, &saved); {
	case errors.Is(err, sql.ErrNoRows):
		return fleet.FileBackup{}, fmt.Errorf("server %d: %w", serverID, fleet.ErrNoBackup)
	case err != nil:
		return fleet.FileBackup{}, fmt.Errorf("cannot read the previous file of server %d: %w", serverID, err)
	}

	savedAt, err := parseTime(saved)
	if err != nil {
		return fleet.FileBackup{}, err
	}

	return fleet.FileBackup{
		ServerID: serverID,
		Content:  []byte(content),
		SHA256:   digest,
		SavedAt:  savedAt,
	}, nil
}

// ServerIDs names every server that has a copy.
//
// The content stays where it is. The servers page only needs to know which rows
// have something to offer, and a file per row would be the whole fleet's DNS
// records rendered into a table nobody asked for.
func (b *Backups) ServerIDs(ctx context.Context) (map[int64]bool, error) {
	rows, err := b.db.QueryContext(ctx, "SELECT server_id FROM file_backups")
	if err != nil {
		return nil, fmt.Errorf("cannot list the stored files: %w", err)
	}
	defer rows.Close()

	held := map[int64]bool{}
	for rows.Next() {
		var serverID int64
		if err := rows.Scan(&serverID); err != nil {
			return nil, fmt.Errorf("cannot read a stored file row: %w", err)
		}
		held[serverID] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot read the stored file rows: %w", err)
	}
	return held, nil
}
