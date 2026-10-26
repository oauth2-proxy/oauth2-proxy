package validation

import (
	"path/filepath"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/stretchr/testify/require"
)

func TestValidateSQLiteSessionStore(t *testing.T) {
	opts := options.NewOptions()
	require.Empty(t, validateSQLiteSessionStore(opts))
	opts.Session.Type = options.SQLiteSessionStoreType
	require.NotEmpty(t, validateSQLiteSessionStore(opts))
	opts.Session.SQLite.Path = "relative.sqlite"
	require.NotEmpty(t, validateSQLiteSessionStore(opts))
	opts.Session.SQLite.Path = filepath.Join(t.TempDir(), "sessions.sqlite")
	require.Empty(t, validateSQLiteSessionStore(opts))
}
