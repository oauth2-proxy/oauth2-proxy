package sqlite

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSQLiteConcurrentInitialization(t *testing.T) {
	if path := os.Getenv("OAUTH2_PROXY_SQLITE_INIT_PATH"); path != "" {
		fmt.Println("ready")
		_, err := io.Copy(io.Discard, os.Stdin)
		require.NoError(t, err)
		store := openTestStore(t, path)
		require.NoError(t, store.Save(t.Context(), fmt.Sprint(os.Getpid()), []byte("initialized"), time.Hour))
		return
	}

	// Start separate processes behind a barrier so they all see a new database.
	for attempt := range 3 {
		t.Run(fmt.Sprint(attempt), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			path := filepath.Join(t.TempDir(), "sessions.sqlite")
			type child struct {
				cmd    *exec.Cmd
				gate   io.WriteCloser
				stdout *bufio.Reader
				stderr bytes.Buffer
			}
			children := make([]child, 8)
			for i := range children {
				c := &children[i]
				c.cmd = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSQLiteConcurrentInitialization$")
				c.cmd.Env = append(os.Environ(), "OAUTH2_PROXY_SQLITE_INIT_PATH="+path)
				var err error
				c.gate, err = c.cmd.StdinPipe()
				require.NoError(t, err)
				stdout, err := c.cmd.StdoutPipe()
				require.NoError(t, err)
				c.stdout = bufio.NewReader(stdout)
				c.cmd.Stderr = &c.stderr
				require.NoError(t, c.cmd.Start())
			}
			for i := range children {
				ready, err := children[i].stdout.ReadString('\n')
				require.NoError(t, err)
				require.Equal(t, "ready\n", ready)
			}
			for i := range children {
				require.NoError(t, children[i].gate.Close())
			}
			for i := range children {
				c := &children[i]
				output, err := io.ReadAll(c.stdout)
				require.NoError(t, err)
				if err := c.cmd.Wait(); err != nil {
					t.Errorf("initializer %d: %v\n%s%s", i, err, output, c.stderr.String())
				}
			}
			store := openTestStore(t, path)
			var count int
			require.NoError(t, store.db.QueryRow("SELECT count(*) FROM sessions").Scan(&count))
			require.Equal(t, len(children), count)
		})
	}
}

func TestSQLiteSchemaVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.sqlite")
	store := openTestStore(t, path)
	ctx := t.Context()
	var version int
	require.NoError(t, store.db.QueryRow("PRAGMA user_version").Scan(&version))
	require.Equal(t, schemaVersion, version)
	require.NoError(t, store.Save(ctx, "existing", []byte("payload"), time.Hour))
	// Databases created before versioning must retain their sessions.
	_, err := store.db.Exec("PRAGMA user_version=0")
	require.NoError(t, err)
	require.NoError(t, store.Close())
	store = openTestStore(t, path)
	require.NoError(t, store.db.QueryRow("PRAGMA user_version").Scan(&version))
	require.Equal(t, schemaVersion, version)
	value, err := store.Load(ctx, "existing")
	require.NoError(t, err)
	require.Equal(t, []byte("payload"), value)

	_, err = store.db.Exec("PRAGMA user_version=2")
	require.NoError(t, err)
	require.NoError(t, store.Close())
	_, err = newStore(path)
	require.ErrorContains(t, err, "unsupported SQLite session schema version 2")
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	defer db.Close()
	require.NoError(t, db.QueryRow("PRAGMA user_version").Scan(&version))
	require.Equal(t, 2, version, "an older binary must not reset the schema version")
}

func TestSQLiteCurrentSchemaDoesNotNeedWriterLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.sqlite")
	store := openTestStore(t, path)
	tx, err := store.db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer tx.Rollback()
	// Another connection holds the writer; opening a current schema needs only reads.
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	require.NoError(t, initialize(ctx, store.db))
}

func TestSQLiteInitializationRollsBackOnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.sqlite")
	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	defer db.Close()
	_, err = db.Exec("CREATE TABLE sessions(key TEXT PRIMARY KEY, expires_at INTEGER)")
	require.NoError(t, err)
	_, err = newStore(path)
	require.ErrorContains(t, err, "value")
	var version, locks int
	require.NoError(t, db.QueryRow("PRAGMA user_version").Scan(&version))
	require.Zero(t, version)
	require.NoError(t, db.QueryRow("SELECT count(*) FROM sqlite_schema WHERE name='session_locks'").Scan(&locks))
	require.Zero(t, locks, "failed initialization must not leave a partial schema")
}

func TestSQLiteInitializationRetryHonorsCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.sqlite")
	store := openTestStore(t, path)
	_, err := store.db.Exec("PRAGMA user_version=0")
	require.NoError(t, err)
	tx, err := store.db.BeginTx(t.Context(), nil)
	require.NoError(t, err)
	defer tx.Rollback()
	// Force BUSY immediately so this exercises our retry deadline, not SQLite's timeout.
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(0)&_txlock=immediate")
	require.NoError(t, err)
	defer db.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	require.ErrorIs(t, initialize(ctx, db), context.DeadlineExceeded)
}
