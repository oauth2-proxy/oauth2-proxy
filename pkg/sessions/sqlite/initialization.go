package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

const schemaVersion = 1

func initialize(ctx context.Context, db *sql.DB) error {
	for {
		err := initializeOnce(ctx, db)
		var sqliteErr *sqlite.Error
		if !errors.As(err, &sqliteErr) || sqliteErr.Code()&0xff != sqlite3.SQLITE_BUSY {
			return err
		}
		// WAL setup and lock upgrades can return BUSY without using busy_timeout.
		// initializeOnce releases its transaction before we retry.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func initializeOnce(ctx context.Context, db *sql.DB) error {
	var version int
	if err := db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version != 0 && version != schemaVersion {
		return fmt.Errorf("unsupported SQLite session schema version %d (supported: %d)", version, schemaVersion)
	}

	// WAL mode is persistent and cannot be enabled inside a transaction.
	var mode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		return err
	}
	if mode != "wal" {
		if err := db.QueryRowContext(ctx, "PRAGMA journal_mode=WAL").Scan(&mode); err != nil {
			return err
		}
		if mode != "wal" {
			return fmt.Errorf("SQLite session database requires WAL mode, got %q", mode)
		}
	}
	if version == schemaVersion {
		return nil
	}

	// The DSN's _txlock=immediate makes this BEGIN IMMEDIATE. Check again after
	// acquiring the write lock: another instance may have initialized the schema.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version == schemaVersion {
		return nil
	}
	if version != 0 {
		return fmt.Errorf("unsupported SQLite session schema version %d (supported: %d)", version, schemaVersion)
	}
	_, err = tx.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS sessions (
			key TEXT PRIMARY KEY NOT NULL,
			value BLOB NOT NULL,
			expires_at INTEGER
		);
		CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
		CREATE TABLE IF NOT EXISTS session_locks (
			key TEXT PRIMARY KEY NOT NULL,
			owner TEXT NOT NULL,
			expires_at INTEGER NOT NULL
		);
		CREATE INDEX IF NOT EXISTS session_locks_expiry ON session_locks(expires_at);
	`)
	if err != nil {
		return err
	}
	// Check required columns before adopting an existing, unversioned database.
	for _, query := range []string{
		"SELECT key, value, expires_at FROM sessions LIMIT 0",
		"SELECT key, owner, expires_at FROM session_locks LIMIT 0",
	} {
		rows, err := tx.QueryContext(ctx, query)
		if err != nil {
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "PRAGMA user_version=1"); err != nil {
		return err
	}
	return tx.Commit()
}
