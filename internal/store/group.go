package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"unbound-web/internal/server"
)

// Groups stores the server groups and their membership.
type Groups struct {
	db *sql.DB
}

// NewGroups builds the group store.
func NewGroups(db *sql.DB) *Groups { return &Groups{db: db} }

// Create inserts a group with its members.
func (g *Groups) Create(ctx context.Context, group server.Group) (server.Group, error) {
	tx, err := g.db.BeginTx(ctx, nil)
	if err != nil {
		return server.Group{}, fmt.Errorf("cannot start the transaction: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx,
		"INSERT INTO server_groups (name, description) VALUES (?, ?)",
		group.Name, group.Description)
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

	if err := replaceMembers(ctx, tx, id, group.ServerIDs); err != nil {
		return server.Group{}, err
	}
	if err := tx.Commit(); err != nil {
		return server.Group{}, fmt.Errorf("cannot commit the group: %w", err)
	}
	return g.Get(ctx, id)
}

// Update writes the group and replaces its membership.
//
// Membership is replaced rather than merged, because the form submits the
// whole set and a merge would make unchecking a server do nothing.
func (g *Groups) Update(ctx context.Context, group server.Group) error {
	tx, err := g.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cannot start the transaction: %w", err)
	}
	defer tx.Rollback()

	result, err := tx.ExecContext(ctx,
		"UPDATE server_groups SET name = ?, description = ? WHERE id = ?",
		group.Name, group.Description, group.ID)
	if err != nil {
		if isUniqueViolation(err) {
			return fmt.Errorf("%w: %s", server.ErrNameTaken, group.Name)
		}
		return fmt.Errorf("cannot update the group: %w", err)
	}
	if err := requireOneRow(result, "group", fmt.Sprint(group.ID)); err != nil {
		return err
	}

	if err := replaceMembers(ctx, tx, group.ID, group.ServerIDs); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("cannot commit the group: %w", err)
	}
	return nil
}

// replaceMembers rewrites the membership of one group.
func replaceMembers(ctx context.Context, tx *sql.Tx, groupID int64, serverIDs []int64) error {
	if _, err := tx.ExecContext(ctx,
		"DELETE FROM server_group_members WHERE group_id = ?", groupID); err != nil {
		return fmt.Errorf("cannot clear the group membership: %w", err)
	}

	for _, serverID := range serverIDs {
		_, err := tx.ExecContext(ctx,
			"INSERT INTO server_group_members (group_id, server_id) VALUES (?, ?)",
			groupID, serverID)
		if err != nil {
			return fmt.Errorf("cannot add server %d to the group: %w", serverID, err)
		}
	}
	return nil
}

// Get reads one group with its membership.
func (g *Groups) Get(ctx context.Context, id int64) (server.Group, error) {
	var group server.Group
	var created, updated string

	err := g.db.QueryRowContext(ctx,
		"SELECT id, name, description, created_at, updated_at FROM server_groups WHERE id = ?", id).
		Scan(&group.ID, &group.Name, &group.Description, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return server.Group{}, fmt.Errorf("group %d: %w", id, ErrNotFound)
	}
	if err != nil {
		return server.Group{}, fmt.Errorf("cannot read the group: %w", err)
	}

	if group.CreatedAt, err = parseTime(created); err != nil {
		return server.Group{}, err
	}
	if group.UpdatedAt, err = parseTime(updated); err != nil {
		return server.Group{}, err
	}

	group.ServerIDs, err = g.memberIDs(ctx, id)
	if err != nil {
		return server.Group{}, err
	}
	return group, nil
}

// memberIDs returns the servers of one group.
func (g *Groups) memberIDs(ctx context.Context, groupID int64) ([]int64, error) {
	rows, err := g.db.QueryContext(ctx, `
SELECT m.server_id
  FROM server_group_members m
  JOIN servers s ON s.id = m.server_id
 WHERE m.group_id = ?
 ORDER BY s.name`, groupID)
	if err != nil {
		return nil, fmt.Errorf("cannot read the group membership: %w", err)
	}
	defer rows.Close()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("cannot read a membership row: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot read the membership rows: %w", err)
	}
	return ids, nil
}

// List returns every group with its membership.
func (g *Groups) List(ctx context.Context) ([]server.Group, error) {
	rows, err := g.db.QueryContext(ctx,
		"SELECT id, name, description, created_at, updated_at FROM server_groups ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("cannot list the groups: %w", err)
	}
	defer rows.Close()

	var groups []server.Group
	for rows.Next() {
		var group server.Group
		var created, updated string

		if err := rows.Scan(&group.ID, &group.Name, &group.Description, &created, &updated); err != nil {
			return nil, fmt.Errorf("cannot read a group row: %w", err)
		}
		if group.CreatedAt, err = parseTime(created); err != nil {
			return nil, err
		}
		if group.UpdatedAt, err = parseTime(updated); err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot read the group rows: %w", err)
	}

	// The membership query runs after the rows are closed, because the pool
	// holds a single connection and a nested query would deadlock on it.
	for i := range groups {
		if groups[i].ServerIDs, err = g.memberIDs(ctx, groups[i].ID); err != nil {
			return nil, err
		}
	}
	return groups, nil
}

// Members returns the servers of one group, ordered by name.
func (g *Groups) Members(ctx context.Context, groupID int64) ([]server.Server, error) {
	rows, err := g.db.QueryContext(ctx, `
SELECT`+serverColumns+`
  FROM servers
  JOIN server_group_members m ON m.server_id = servers.id
 WHERE m.group_id = ?
 ORDER BY servers.name`, groupID)
	if err != nil {
		return nil, fmt.Errorf("cannot read the group members: %w", err)
	}
	defer rows.Close()

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

// Delete removes a group. The membership rows follow through the foreign key,
// and the servers themselves stay.
func (g *Groups) Delete(ctx context.Context, id int64) error {
	result, err := g.db.ExecContext(ctx, "DELETE FROM server_groups WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("cannot delete the group: %w", err)
	}
	return requireOneRow(result, "group", fmt.Sprint(id))
}
