package sessions_test

import (
	"io"
	"path/filepath"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/persistence"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/sqlite"
	"github.com/stretchr/testify/require"
)

func TestSQLiteFactory(t *testing.T) {
	opts := options.NewOptions()
	opts.Session.Type = options.SQLiteSessionStoreType
	opts.Session.SQLite.Path = filepath.Join(t.TempDir(), "sessions.sqlite")
	store, err := sessions.NewSessionStore(&opts.Session, &opts.Cookie)
	require.NoError(t, err)
	backend := store.(*persistence.Manager).Store.(*sqlite.SessionStore)
	require.NoError(t, backend.VerifyConnection(t.Context()))
	require.NoError(t, store.(io.Closer).Close())
	require.Error(t, backend.VerifyConnection(t.Context()))
}
