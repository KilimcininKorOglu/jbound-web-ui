package store

import (
	"context"
	"database/sql"
	"fmt"
)

// Settings stores the values an operator changed on the settings page.
type Settings struct {
	db *sql.DB
}

// NewSettings builds the settings store.
func NewSettings(db *sql.DB) *Settings { return &Settings{db: db} }

// Load returns every stored setting.
//
// A key with no row is not an error. The registry default answers for it, so a
// panel that has never been configured reads the same as one that was
// configured with the defaults.
func (s *Settings) Load(ctx context.Context) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT key, value FROM settings")
	if err != nil {
		return nil, fmt.Errorf("cannot read the settings: %w", err)
	}
	defer rows.Close()

	values := map[string]string{}
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, fmt.Errorf("cannot read a setting: %w", err)
		}
		values[key] = value
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cannot read the setting rows: %w", err)
	}
	return values, nil
}

// Save writes every value of one submission in a single transaction.
//
// All or nothing, because half a submission would leave the panel running on a
// combination the operator never approved and that the cross field rules never
// saw.
func (s *Settings) Save(ctx context.Context, values map[string]string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cannot start the transaction: %w", err)
	}
	defer tx.Rollback()

	const query = `
INSERT INTO settings (key, value, updated_at)
VALUES (?, ?, strftime('%Y-%m-%d %H:%M:%S', 'now'))
ON CONFLICT (key) DO UPDATE
   SET value = excluded.value,
       updated_at = excluded.updated_at`

	statement, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("cannot prepare the setting statement: %w", err)
	}
	defer statement.Close()

	for key, value := range values {
		if _, err := statement.ExecContext(ctx, key, value); err != nil {
			return fmt.Errorf("cannot store the setting %s: %w", key, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("cannot commit the settings: %w", err)
	}
	return nil
}
