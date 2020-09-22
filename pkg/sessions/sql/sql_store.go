package sql

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	// load the driver
	_ "github.com/lib/pq"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/persistence"
)

// SessionStore is an implementation of the persistence.Store
// interface that stores sessions in a SQL database
type SessionStore struct {
	pool  *sql.DB
	table string
}

// NewSQLSessionStore initialises a new instance of the SessionStore and wraps
// it in a persistence.Manager
func NewSQLSessionStore(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessions.SessionStore, error) {
	table := opts.SQL.TablePrefix + "_sessions"
	pool, err := sql.Open(opts.SQL.Driver, opts.SQL.DSN)
	if err != nil {
		return nil, fmt.Errorf("error constructing SQL client: %w", err)
	}
	_, err = pool.Exec(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
            key text primary key,
            value bytea,
            expires timestamp)`, table))
	if err != nil {
		return nil, fmt.Errorf("error creating table: %w", err)
	}
	_, err = pool.Exec(fmt.Sprintf(`BEGIN;
        CREATE INDEX IF NOT EXISTS exp_idx ON %s (expires);
        CREATE OR REPLACE FUNCTION f_delete_expired () RETURNS trigger
            AS 'BEGIN DELETE FROM TG_TABLE_NAME WHERE expires < current_timestamp; RETURN NULL; END' LANGUAGE PLPGSQL;
        DROP TRIGGER IF EXISTS t_delete_expired ON %s;
        CREATE TRIGGER t_delete_expired BEFORE INSERT ON %s
            EXECUTE PROCEDURE f_delete_expired();
        COMMIT;`, table, table, table))
	if err != nil {
		return nil, fmt.Errorf("error creating trigger: %w", err)
	}
	ss := &SessionStore{
		pool:  pool,
		table: table,
	}
	return persistence.NewManager(ss, cookieOpts), nil
}

// Save takes a sessions.SessionState and stores the information from it
// to postgres, and adds a new persistence cookie on the HTTP response writer
func (store *SessionStore) Save(ctx context.Context, key string, value []byte, exp time.Duration) error {
	_, err := store.pool.ExecContext(ctx, fmt.Sprintf(
		`INSERT INTO %s VALUES ($1, $2, current_timestamp + $3)
                ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, expires = EXCLUDED.expires`,
		store.table),
		key, value, exp.Seconds())
	if err != nil {
		return fmt.Errorf("error saving SQL session: %w", err)
	}
	return nil
}

// Load reads sessions.SessionState information from a persistence
// cookie within the HTTP request object
func (store *SessionStore) Load(ctx context.Context, key string) ([]byte, error) {
	var value []byte
	err := store.pool.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT value FROM %s WHERE key = $1 AND expires > current_timestamp`, store.table), key).Scan(&value)
	if err != nil {
		return nil, fmt.Errorf("error loading SQL session: %w", err)
	}
	return value, nil
}

// Clear clears any saved session information for a given persistence cookie
// from postgres, and then clears the session
func (store *SessionStore) Clear(ctx context.Context, key string) error {
	_, err := store.pool.ExecContext(ctx, fmt.Sprintf(`DELETE FROM %s WHERE key = $1`, store.table), key)
	if err != nil {
		return fmt.Errorf("error clearing the session from SQL: %w", err)
	}
	return nil
}
