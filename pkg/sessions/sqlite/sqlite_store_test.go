package sqlite

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/persistence"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/tests"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSQLiteSessionStore(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "SQLite SessionStore")
}

var _ = Describe("SQLite persistent session contract", func() {
	var store *SessionStore
	tests.RunSessionStoreTests(func(opts *options.SessionOptions, cookies *options.Cookie) (sessionsapi.SessionStore, error) {
		opts.SQLite.Path = filepath.Join(GinkgoT().TempDir(), "sessions.sqlite")
		manager, err := NewSQLiteSessionStore(opts, cookies)
		if err == nil {
			store = manager.(*persistence.Manager).Store.(*SessionStore)
			DeferCleanup(store.Close)
		}
		return manager, err
	}, func(d time.Duration) error {
		_, err := store.db.Exec("UPDATE sessions SET expires_at = expires_at - ?", d.Nanoseconds())
		if err == nil {
			_, err = store.db.Exec("UPDATE session_locks SET expires_at = expires_at - ?", d.Nanoseconds())
		}
		return err
	})
})

func openTestStore(t *testing.T, path string) *SessionStore {
	t.Helper()
	store, err := newStore(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	return store
}

func TestSQLiteStorage(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "sessions ?#%.sqlite")
	a := openTestStore(t, path)
	b := openTestStore(t, path)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
	require.NoError(t, a.VerifyConnection(ctx))
	var journalMode string
	require.NoError(t, a.db.QueryRow("PRAGMA journal_mode").Scan(&journalMode))
	require.Equal(t, "wal", journalMode)

	require.NoError(t, a.Save(ctx, "ticket", []byte("first"), time.Hour))
	value, err := b.Load(ctx, "ticket")
	require.NoError(t, err)
	require.Equal(t, "first", string(value))
	require.NoError(t, b.Save(ctx, "ticket", []byte("updated"), time.Hour))
	value, err = a.Load(ctx, "ticket")
	require.NoError(t, err)
	require.Equal(t, "updated", string(value))
	_, err = a.db.Exec("UPDATE sessions SET expires_at = 0 WHERE key = 'ticket'")
	require.NoError(t, err)
	_, err = b.Load(ctx, "ticket")
	require.Error(t, err, "expiry must not depend on cleanup")
	require.NoError(t, b.Save(ctx, "permanent", []byte("no TTL"), 0))
	var count int
	require.NoError(t, a.db.QueryRow("SELECT count(*) FROM sessions WHERE key = 'ticket'").Scan(&count))
	require.Zero(t, count, "writes reclaim expired sessions")
	_, err = a.Load(ctx, "permanent")
	require.NoError(t, err)
	require.NoError(t, a.Clear(ctx, "permanent"))
	require.NoError(t, a.Clear(ctx, "permanent"), "clear is idempotent")
	_, err = b.Load(ctx, "permanent")
	require.Error(t, err)
	require.Error(t, a.Save(ctx, "bad-ttl", []byte("value"), -time.Second))
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	require.Error(t, a.Save(canceled, "canceled", []byte("value"), time.Hour))
	_, err = a.Load(canceled, "ticket")
	require.Error(t, err)
}

func TestSQLiteInvalidPath(t *testing.T) {
	for _, path := range []string{"", "relative.sqlite", ":memory:", "file:/tmp/sessions", t.TempDir(), filepath.Join(t.TempDir(), "missing", "db")} {
		_, err := newStore(path)
		require.Error(t, err, path)
	}
}

func TestSQLiteTicketSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sessions.sqlite")
	opts := &options.SessionOptions{SQLite: options.SQLiteStoreOptions{Path: path}}
	cookies := &options.Cookie{Name: "session", Secret: strings.Repeat("s", 32), Path: "/", Expire: time.Hour, Secure: true, HTTPOnly: true}
	first, err := NewSQLiteSessionStore(opts, cookies)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	response := httptest.NewRecorder()
	token := strings.Repeat("large-access-token", 1000)
	require.NoError(t, first.Save(response, req, &sessionsapi.SessionState{AccessToken: token, Email: "test@example.com"}))
	result := response.Result()
	defer result.Body.Close()
	require.Len(t, result.Cookies(), 1)
	require.Less(t, len(result.Cookies()[0].String()), 512, "session size must not affect ticket size")
	req.AddCookie(result.Cookies()[0])
	store := first.(*persistence.Manager).Store.(*SessionStore)
	var payload []byte
	require.NoError(t, store.db.QueryRow("SELECT value FROM sessions").Scan(&payload))
	require.NotContains(t, string(payload), "large-access-token", "reuse persistence.Manager encryption")
	require.NoError(t, store.Close())

	second, err := NewSQLiteSessionStore(opts, cookies)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, second.(*persistence.Manager).Store.(*SessionStore).Close()) })
	session, err := second.Load(req)
	require.NoError(t, err)
	require.Equal(t, token, session.AccessToken)
	tampered := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	badCookie := *result.Cookies()[0]
	badCookie.Value += "changed"
	tampered.AddCookie(&badCookie)
	_, err = second.Load(tampered)
	require.Error(t, err)
	require.NoError(t, second.Clear(httptest.NewRecorder(), req))
	_, err = second.Load(req)
	require.Error(t, err, "replaying a signed cookie after logout must fail")
}

func TestSQLiteLocks(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "sessions.sqlite")
	a, b := openTestStore(t, path), openTestStore(t, path)
	first, second := a.Lock("session"), b.Lock("session")
	require.NoError(t, first.Obtain(ctx, time.Minute))
	require.ErrorIs(t, second.Obtain(ctx, time.Minute), sessionsapi.ErrLockNotObtained)
	require.ErrorIs(t, second.Release(ctx), sessionsapi.ErrNotLocked)
	require.ErrorIs(t, second.Refresh(ctx, time.Minute), sessionsapi.ErrNotLocked)
	held, err := second.Peek(ctx)
	require.NoError(t, err)
	require.True(t, held)
	require.NoError(t, first.Refresh(ctx, time.Hour))
	_, err = a.db.Exec("UPDATE session_locks SET expires_at = 0")
	require.NoError(t, err)
	require.ErrorIs(t, first.Refresh(ctx, time.Minute), sessionsapi.ErrNotLocked)
	require.NoError(t, second.Obtain(ctx, time.Minute), "a crashed process's expired lease must be reclaimable")
	require.ErrorIs(t, first.Release(ctx), sessionsapi.ErrNotLocked, "old holder must not delete the replacement lease")
	require.ErrorIs(t, first.Refresh(ctx, time.Minute), sessionsapi.ErrNotLocked)
	require.NoError(t, second.Release(ctx))
	held, err = first.Peek(ctx)
	require.NoError(t, err)
	require.False(t, held)
	require.Error(t, first.Obtain(ctx, 0))

	var winners atomic.Int32
	var wg sync.WaitGroup
	for i := range 24 {
		wg.Go(func() {
			store := a
			if i%2 == 0 {
				store = b
			}
			err := store.Lock("contested").Obtain(ctx, time.Minute)
			if err == nil {
				winners.Add(1)
			} else {
				assert.ErrorIs(t, err, sessionsapi.ErrLockNotObtained)
			}
		})
	}
	wg.Wait()
	require.Equal(t, int32(1), winners.Load())
}

func TestSQLiteAcrossProcesses(t *testing.T) {
	if path := os.Getenv("OAUTH2_PROXY_SQLITE_TEST_PATH"); path != "" {
		store := openTestStore(t, path)
		value, err := store.Load(t.Context(), "shared")
		require.NoError(t, err)
		require.Equal(t, "parent", string(value))
		require.ErrorIs(t, store.Lock("shared").Obtain(t.Context(), time.Minute), sessionsapi.ErrLockNotObtained)
		require.NoError(t, store.Save(t.Context(), "child", []byte("visible"), time.Hour))
		return
	}
	path := filepath.Join(t.TempDir(), "sessions.sqlite")
	store := openTestStore(t, path)
	require.NoError(t, store.Save(t.Context(), "shared", []byte("parent"), time.Hour))
	require.NoError(t, store.Lock("shared").Obtain(t.Context(), time.Minute))
	child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSQLiteAcrossProcesses$")
	child.Env = append(os.Environ(), "OAUTH2_PROXY_SQLITE_TEST_PATH="+path)
	output, err := child.CombinedOutput()
	require.NoError(t, err, string(output))
	value, err := store.Load(t.Context(), "child")
	require.NoError(t, err)
	require.Equal(t, "visible", string(value))
}

func TestSQLiteLeaseStartsAfterWriterWait(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "sessions.sqlite"))
	ctx := t.Context()
	writer, err := store.db.Conn(ctx)
	require.NoError(t, err)
	defer writer.Close()
	_, err = writer.ExecContext(ctx, "BEGIN IMMEDIATE")
	require.NoError(t, err)
	defer writer.ExecContext(ctx, "ROLLBACK")
	lease := store.Lock("blocked")
	result := make(chan error, 1)
	go func() { result <- lease.Obtain(ctx, 200*time.Millisecond) }()
	// Hold the writer longer than the requested lease, but below busy_timeout.
	select {
	case err := <-result:
		t.Fatalf("lease completed while writer was held: %v", err)
	case <-time.After(400 * time.Millisecond):
	}
	_, err = writer.ExecContext(ctx, "COMMIT")
	require.NoError(t, err)
	require.NoError(t, <-result)
	held, err := lease.Peek(ctx)
	require.NoError(t, err)
	require.True(t, held, "waiting for the writer must not consume the new lease")
	require.NoError(t, lease.Release(ctx))
}

func TestSQLiteUnavailableFailsClosed(t *testing.T) {
	store, err := newStore(filepath.Join(t.TempDir(), "sessions.sqlite"))
	require.NoError(t, err)
	require.NoError(t, store.Close())
	_, err = store.Load(t.Context(), "session")
	require.Error(t, err)
	require.Error(t, store.Save(t.Context(), "session", []byte("payload"), time.Minute))
	require.Error(t, store.Clear(t.Context(), "session"))
	require.Error(t, store.VerifyConnection(t.Context()))
	require.Error(t, store.Lock("session").Obtain(t.Context(), time.Minute))
}
