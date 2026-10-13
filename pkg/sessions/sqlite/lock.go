package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

// A lease spans the provider request without keeping a SQLite write transaction open.
// The random owner prevents an expired holder from releasing a replacement lease.
type lock struct {
	db    *sql.DB
	key   string
	owner string
}

// Evaluate time inside SQLite, after waiting for a writer. Computing the lease
// deadline before a busy wait could return a lease that has already expired.
const sqliteNow = "CAST(unixepoch('subsec') * 1000000000 AS INTEGER)"

func (l *lock) Obtain(ctx context.Context, expiration time.Duration) error {
	if expiration <= 0 {
		return errors.New("SQLite lock expiration must be positive")
	}
	if _, err := l.db.ExecContext(ctx, `DELETE FROM session_locks WHERE key IN
		(SELECT key FROM session_locks WHERE expires_at <= `+sqliteNow+` LIMIT 100)`); err != nil {
		return err
	}
	owner := rand.Text()
	result, err := l.db.ExecContext(ctx, `INSERT INTO session_locks(key, owner, expires_at) VALUES (?, ?, `+sqliteNow+` + ?)
		ON CONFLICT(key) DO UPDATE SET owner=excluded.owner, expires_at=excluded.expires_at
		WHERE session_locks.expires_at <= `+sqliteNow, l.key, owner, expiration.Nanoseconds())
	if err := changedRow(result, err, sessions.ErrLockNotObtained); err != nil {
		return err
	}
	l.owner = owner
	return nil
}

func (l *lock) Peek(ctx context.Context) (bool, error) {
	var exists bool
	err := l.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM session_locks WHERE key = ? AND expires_at > "+sqliteNow+")",
		l.key).Scan(&exists)
	return exists, err
}

func (l *lock) Refresh(ctx context.Context, expiration time.Duration) error {
	if expiration <= 0 {
		return errors.New("SQLite lock expiration must be positive")
	}
	result, err := l.db.ExecContext(ctx, `UPDATE session_locks SET expires_at = `+sqliteNow+` + ?
		WHERE key = ? AND owner = ? AND expires_at > `+sqliteNow, expiration.Nanoseconds(), l.key, l.owner)
	return changedRow(result, err, sessions.ErrNotLocked)
}

func (l *lock) Release(ctx context.Context) error {
	result, err := l.db.ExecContext(ctx, "DELETE FROM session_locks WHERE key = ? AND owner = ? AND expires_at > "+sqliteNow,
		l.key, l.owner)
	return changedRow(result, err, sessions.ErrNotLocked)
}

func changedRow(result sql.Result, err error, unchanged error) error {
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return unchanged
	}
	return nil
}
