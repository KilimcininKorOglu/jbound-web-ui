package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"unbound-web/internal/server"
)

// Servers stores the managed DNS servers.
type Servers struct {
	db *sql.DB
}

// NewServers builds the server store.
func NewServers(db *sql.DB) *Servers { return &Servers{db: db} }

// serverColumns is the read projection. It leaves out nothing, because every
// field is shown somewhere in the interface.
const serverColumns = `
    id, name, host, ssh_port, transport, ssh_user, ssh_key_path, host_key,
    host_entries_path, reload_cmd, status_cmd,
    base64_path, tee_path, mv_path, sha256_path,
    enabled, last_seen_at, last_error, created_at, updated_at`

// Create inserts a server and returns it with its identifier.
func (s *Servers) Create(ctx context.Context, record server.Server) (server.Server, error) {
	const query = `
INSERT INTO servers
    (name, host, ssh_port, transport, ssh_user, ssh_key_path, host_key,
     host_entries_path, reload_cmd, status_cmd,
     base64_path, tee_path, mv_path, sha256_path, enabled)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	result, err := s.db.ExecContext(ctx, query,
		record.Name, record.Host, record.SSHPort, record.Transport,
		record.SSHUser, record.SSHKeyPath, record.HostKey,
		record.HostEntriesPath, record.ReloadCmd, record.StatusCmd,
		record.Base64Path, record.TeePath, record.MvPath, record.Sha256Path,
		boolToInt(record.Enabled),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return server.Server{}, fmt.Errorf("%w: %s", server.ErrNameTaken, record.Name)
		}
		return server.Server{}, fmt.Errorf("cannot insert the server: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return server.Server{}, fmt.Errorf("cannot read the new server id: %w", err)
	}
	return s.Get(ctx, id)
}

// Update writes the editable fields of a server.
//
// The host key is not among them. Approving a key is its own action, so a
// routine edit cannot quietly trust a different server.
func (s *Servers) Update(ctx context.Context, record server.Server) error {
	const query = `
UPDATE servers
   SET name = ?, host = ?, ssh_port = ?, ssh_user = ?,
       host_entries_path = ?, reload_cmd = ?, status_cmd = ?,
       base64_path = ?, tee_path = ?, mv_path = ?, sha256_path = ?,
       enabled = ?
 WHERE id = ?`

	result, err := s.db.ExecContext(ctx, query,
		record.Name, record.Host, record.SSHPort, record.SSHUser,
		record.HostEntriesPath, record.ReloadCmd, record.StatusCmd,
		record.Base64Path, record.TeePath, record.MvPath, record.Sha256Path,
		boolToInt(record.Enabled), record.ID,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: %s", server.ErrNameTaken, record.Name)
		}
		return fmt.Errorf("cannot update the server: %w", err)
	}
	return requireOneRow(result, "server", fmt.Sprint(record.ID))
}

// SetKeyPath records where the private key of a server lives.
//
// It is its own statement because the key file is named after the row, so the
// path is only known once the row exists.
func (s *Servers) SetKeyPath(ctx context.Context, id int64, relPath string) error {
	result, err := s.db.ExecContext(ctx,
		"UPDATE servers SET ssh_key_path = ? WHERE id = ?", relPath, id)
	if err != nil {
		return fmt.Errorf("cannot store the key path: %w", err)
	}
	return requireOneRow(result, "server", fmt.Sprint(id))
}

// SetHostKey records an approved host key.
func (s *Servers) SetHostKey(ctx context.Context, id int64, hostKey string) error {
	result, err := s.db.ExecContext(ctx,
		"UPDATE servers SET host_key = ? WHERE id = ?", hostKey, id)
	if err != nil {
		return fmt.Errorf("cannot store the host key: %w", err)
	}
	return requireOneRow(result, "server", fmt.Sprint(id))
}

// SetReachability records the outcome of the last contact.
func (s *Servers) SetReachability(ctx context.Context, id int64, at time.Time, failure string) error {
	const query = `UPDATE servers SET last_seen_at = ?, last_error = ? WHERE id = ?`

	var seen any
	if failure == "" {
		seen = formatTime(at)
	}

	result, err := s.db.ExecContext(ctx, query, seen, failure, id)
	if err != nil {
		return fmt.Errorf("cannot record the server reachability: %w", err)
	}
	return requireOneRow(result, "server", fmt.Sprint(id))
}

// Get reads one server.
func (s *Servers) Get(ctx context.Context, id int64) (server.Server, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT"+serverColumns+" FROM servers WHERE id = ?", id)

	record, err := scanServer(row)
	if errors.Is(err, sql.ErrNoRows) {
		return server.Server{}, fmt.Errorf("server %d: %w", id, ErrNotFound)
	}
	if err != nil {
		return server.Server{}, fmt.Errorf("cannot read the server: %w", err)
	}
	return record, nil
}

// GetByName reads one server by its name.
func (s *Servers) GetByName(ctx context.Context, name string) (server.Server, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT"+serverColumns+" FROM servers WHERE name = ?", name)

	record, err := scanServer(row)
	if errors.Is(err, sql.ErrNoRows) {
		return server.Server{}, fmt.Errorf("server %s: %w", name, ErrNotFound)
	}
	if err != nil {
		return server.Server{}, fmt.Errorf("cannot read the server: %w", err)
	}
	return record, nil
}

// List returns every server ordered by name.
func (s *Servers) List(ctx context.Context) ([]server.Server, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT"+serverColumns+" FROM servers ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("cannot list the servers: %w", err)
	}
	defer rows.Close()

	var servers []server.Server
	for rows.Next() {
		record, err := scanServer(rows)
		if err != nil {
			return nil, fmt.Errorf("cannot read a server row: %w", err)
		}
		servers = append(servers, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot read the server rows: %w", err)
	}
	return servers, nil
}

// ListEnabled returns the servers a fleet operation may target.
func (s *Servers) ListEnabled(ctx context.Context) ([]server.Server, error) {
	all, err := s.List(ctx)
	if err != nil {
		return nil, err
	}

	enabled := make([]server.Server, 0, len(all))
	for _, record := range all {
		if record.Enabled {
			enabled = append(enabled, record)
		}
	}
	return enabled, nil
}

// Delete removes a server.
//
// The membership rows, the cached records and the per server state follow
// through the foreign keys. The audit rows do not, because what happened on
// that server still has to be answerable afterwards.
func (s *Servers) Delete(ctx context.Context, id int64) error {
	result, err := s.db.ExecContext(ctx, "DELETE FROM servers WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("cannot delete the server: %w", err)
	}
	return requireOneRow(result, "server", fmt.Sprint(id))
}

// scanner covers both a single row and a row from a result set.
type scanner interface {
	Scan(dest ...any) error
}

func scanServer(row scanner) (server.Server, error) {
	var (
		record             server.Server
		enabled            int
		lastSeen           sql.NullString
		created, updated   string
		parsedSeen         time.Time
		errCreated, errUpd error
	)

	err := row.Scan(
		&record.ID, &record.Name, &record.Host, &record.SSHPort,
		&record.Transport, &record.SSHUser, &record.SSHKeyPath, &record.HostKey,
		&record.HostEntriesPath, &record.ReloadCmd, &record.StatusCmd,
		&record.Base64Path, &record.TeePath, &record.MvPath, &record.Sha256Path,
		&enabled, &lastSeen, &record.LastError, &created, &updated,
	)
	if err != nil {
		return server.Server{}, err
	}

	record.Enabled = enabled == 1

	if record.CreatedAt, errCreated = parseTime(created); errCreated != nil {
		return server.Server{}, errCreated
	}
	if record.UpdatedAt, errUpd = parseTime(updated); errUpd != nil {
		return server.Server{}, errUpd
	}
	if lastSeen.Valid && lastSeen.String != "" {
		if parsedSeen, err = parseTime(lastSeen.String); err != nil {
			return server.Server{}, err
		}
		record.LastSeenAt = &parsedSeen
	}
	return record, nil
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// isUniqueViolation reports whether an error comes from a unique constraint.
//
// The driver reports it as a message rather than a typed error, so the text is
// the only thing to match on.
func isUniqueViolation(err error) bool {
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}
