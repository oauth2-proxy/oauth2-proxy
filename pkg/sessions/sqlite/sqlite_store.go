package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/persistence"
	_ "modernc.org/sqlite" // Register the CGO-free SQLite driver.
)

// Evaluate deadlines inside SQLite so waiting for a writer does not consume
// a new session's TTL or a refresh lease's lifetime.
const sqliteNow = "CAST(unixepoch('subsec') * 1000000000 AS INTEGER)"

// SessionStore persists encrypted session payloads on a local filesystem.
// Multiple processes can share the database, but all must run on the same host.
type SessionStore struct {
	db *sql.DB
}

// NewSQLiteSessionStore reuses the persistent store's signed tickets and encryption.
func NewSQLiteSessionStore(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessions.SessionStore, error) {
	store, err := newStore(opts.SQLite.Path)
	if err != nil {
		return nil, err
	}
	return persistence.NewManager(store, cookieOpts), nil
}

func newStore(path string) (*SessionStore, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("sqlite-path must be an absolute local filesystem path")
	}
	// Create with restrictive permissions before SQLite opens the file. The containing
	// directory must already exist and allow creation of the WAL and shared-memory files.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600) // #nosec G703 -- Operator-configured database path, never request input.
	if err != nil {
		return nil, fmt.Errorf("opening SQLite session database: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	u := url.URL{Scheme: "file", Path: path}
	q := u.Query()
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, fmt.Errorf("opening SQLite session database: %w", err)
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = db.ExecContext(ctx, `
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
		_ = db.Close()
		return nil, fmt.Errorf("initializing SQLite session database: %w", err)
	}
	return &SessionStore{db: db}, nil
}

// Save replaces the encrypted payload and its TTL. A zero TTL does not expire.
func (s *SessionStore) Save(ctx context.Context, key string, value []byte, exp time.Duration) error {
	if exp < 0 {
		return errors.New("SQLite session expiration must not be negative")
	}
	var ttl any
	if exp > 0 {
		ttl = exp.Nanoseconds()
	}
	// Reclaim expired records in bounded batches during writes, without a background
	// worker or a database-wide sweep on each read. Load enforces expiry independently.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE key IN
		(SELECT key FROM sessions WHERE expires_at <= `+sqliteNow+` LIMIT 100)`); err != nil {
		return fmt.Errorf("cleaning expired SQLite sessions: %w", err)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO sessions(key, value, expires_at) VALUES (?, ?, `+sqliteNow+` + ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value, expires_at=excluded.expires_at`, key, value, ttl)
	if err != nil {
		return fmt.Errorf("saving SQLite session: %w", err)
	}
	return nil
}

// Load never returns an expired session, even if cleanup has not run yet.
func (s *SessionStore) Load(ctx context.Context, key string) ([]byte, error) {
	var value []byte
	err := s.db.QueryRowContext(ctx, `SELECT value FROM sessions
		WHERE key = ? AND (expires_at IS NULL OR expires_at > `+sqliteNow+`)`, key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("session does not exist or has expired")
	}
	if err != nil {
		return nil, fmt.Errorf("loading SQLite session: %w", err)
	}
	return value, nil
}

// Clear invalidates the ticket on every instance sharing this database.
func (s *SessionStore) Clear(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE key = ?", key)
	return err
}

// Lock creates a process-independent lease for session refreshes.
func (s *SessionStore) Lock(key string) sessions.Lock {
	return &lock{db: s.db, key: key}
}

// VerifyConnection checks that the database is readable.
func (s *SessionStore) VerifyConnection(ctx context.Context) error {
	var count int
	return s.db.QueryRowContext(ctx, "SELECT count(*) FROM (SELECT key FROM sessions LIMIT 1)").Scan(&count)
}

// Close releases the database connections.
func (s *SessionStore) Close() error {
	return s.db.Close()
}

var _ persistence.Store = (*SessionStore)(nil)
