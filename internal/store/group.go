package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"jbound/internal/server"
)

// Groups stores the server groups.
//
// Membership is not written here. A server carries its own group_id, so the
// only thing a group owns is its name, its description and the source a mirror
// copies from.
type Groups struct {
	db *sql.DB
}

// NewGroups builds the group store.
func NewGroups(db *sql.DB) *Groups { return &Groups{db: db} }

// Create inserts a group.
func (g *Groups) Create(ctx context.Context, group server.Group) (server.Group, error) {
	result, err := g.db.ExecContext(ctx,
		"INSERT INTO server_groups (name, description, source_server_id) VALUES (?, ?, ?)",
		group.Name, group.Description, nullableID(group.SourceServerID))
	if err != nil {
		if isUniqueViolation(err) {
			return server.Group{}, fmt.Errorf("%w: %s", server.ErrNameTaken, group.Name)
		}
		return server.Group{}, fmt.Errorf("cannot insert the group: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return server.Group{}, fmt.Errorf("cannot read the new group id: %w", err)
	}
	return g.Get(ctx, id)
}

// Update writes the group.
func (g *Groups) Update(ctx context.Context, group server.Group) error {
	result, err := g.db.ExecContext(ctx,
		"UPDATE server_groups SET name = ?, description = ?, source_server_id = ? WHERE id = ?",
		group.Name, group.Description, nullableID(group.SourceServerID), group.ID)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: %s", server.ErrNameTaken, group.Name)
		}
		return fmt.Errorf("cannot update the group: %w", err)
	}
	return requireOneRow(result, "group", fmt.Sprint(group.ID))
}

// groupColumns names what a group row carries, so the two readers below cannot
// drift apart.
const groupColumns = `id, name, description, source_server_id, created_at, updated_at`

// Get reads one group.
func (g *Groups) Get(ctx context.Context, id int64) (server.Group, error) {
	row := g.db.QueryRowContext(ctx,
		"SELECT "+groupColumns+" FROM server_groups WHERE id = ?", id)

	group, err := scanGroup(row)
	if errors.Is(err, sql.ErrNoRows) {
		return server.Group{}, fmt.Errorf("group %d: %w", id, ErrNotFound)
	}
	if err != nil {
		return server.Group{}, fmt.Errorf("cannot read the group: %w", err)
	}
	return group, nil
}

// List returns every group, ordered by name.
func (g *Groups) List(ctx context.Context) ([]server.Group, error) {
	rows, err := g.db.QueryContext(ctx,
		"SELECT "+groupColumns+" FROM server_groups ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("cannot list the groups: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var groups []server.Group
	for rows.Next() {
		group, err := scanGroup(rows)
		if err != nil {
			return nil, fmt.Errorf("cannot read a group row: %w", err)
		}
		groups = append(groups, group)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot read the group rows: %w", err)
	}
	return groups, nil
}

// Members returns the servers of one group, ordered by name.
func (g *Groups) Members(ctx context.Context, groupID int64) ([]server.Server, error) {
	rows, err := g.db.QueryContext(ctx, `
SELECT`+serverColumns+`
  FROM servers
 WHERE group_id = ?
 ORDER BY name`, groupID)
	if err != nil {
		return nil, fmt.Errorf("cannot read the group members: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var members []server.Server
	for rows.Next() {
		record, err := scanServer(rows)
		if err != nil {
			return nil, fmt.Errorf("cannot read a member row: %w", err)
		}
		members = append(members, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot read the member rows: %w", err)
	}
	return members, nil
}

// Delete removes a group. Its servers stay and are left ungrouped by the
// foreign key.
func (g *Groups) Delete(ctx context.Context, id int64) error {
	result, err := g.db.ExecContext(ctx, "DELETE FROM server_groups WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("cannot delete the group: %w", err)
	}
	return requireOneRow(result, "group", fmt.Sprint(id))
}

// scanGroup reads one group row from a query or a single row.
func scanGroup(row scanner) (server.Group, error) {
	var (
		group   server.Group
		source  sql.NullInt64
		created string
		updated string
	)

	if err := row.Scan(&group.ID, &group.Name, &group.Description,
		&source, &created, &updated); err != nil {
		return server.Group{}, err
	}

	group.SourceServerID = source.Int64

	var err error
	if group.CreatedAt, err = parseTime(created); err != nil {
		return server.Group{}, err
	}
	if group.UpdatedAt, err = parseTime(updated); err != nil {
		return server.Group{}, err
	}
	return group, nil
}

// nullableID writes an optional reference the way the column stores it, so a
// zero identifier lands as NULL rather than as a row nothing points to.
func nullableID(id int64) any {
	if id <= 0 {
		return nil
	}
	return id
}
