package main

import (
	"context"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/sqlite"
	"github.com/stretchr/testify/require"
)

type lifecycleServer func(context.Context) error

func (s lifecycleServer) Start(ctx context.Context) error { return s(ctx) }

func TestProxyClosesSessionStore(t *testing.T) {
	for name, serverErr := range map[string]error{"clean shutdown": nil, "server failure": errors.New("server failed")} {
		t.Run(name, func(t *testing.T) {
			opts := options.NewOptions()
			opts.Session.SQLite.Path = filepath.Join(t.TempDir(), "sessions.sqlite")
			opts.Cookie.Secret = rawCookieSecret
			store, err := sqlite.NewSQLiteSessionStore(&opts.Session, &opts.Cookie)
			require.NoError(t, err)
			t.Cleanup(func() { closeSessionStore(store) })
			req := httptest.NewRequest("GET", "https://example.com/", nil)
			rw := httptest.NewRecorder()
			proxy := &OAuthProxy{sessionStore: store, server: lifecycleServer(func(ctx context.Context) error {
				require.NoError(t, store.VerifyConnection(ctx))
				require.NoError(t, store.Save(rw, req, &sessions.SessionState{Email: "test@example.com"}))
				return serverErr
			})}
			require.ErrorIs(t, proxy.Start(), serverErr)
			require.Error(t, store.VerifyConnection(t.Context()))
			require.NoFileExists(t, opts.Session.SQLite.Path+"-wal", "last close checkpoints the WAL")

			response := rw.Result()
			defer response.Body.Close()
			req.AddCookie(response.Cookies()[0])
			reopened, err := sqlite.NewSQLiteSessionStore(&opts.Session, &opts.Cookie)
			require.NoError(t, err)
			t.Cleanup(func() { closeSessionStore(reopened) })
			session, err := reopened.Load(req)
			require.NoError(t, err)
			require.Equal(t, "test@example.com", session.Email)
		})
	}
}

func TestProxyConstructionFailureClosesSessionStore(t *testing.T) {
	opts := options.NewOptions()
	opts.Session.Type = options.SQLiteSessionStoreType
	opts.Session.SQLite.Path = filepath.Join(t.TempDir(), "sessions.sqlite")
	opts.HtpasswdFile = filepath.Join(t.TempDir(), "missing")
	_, err := NewOAuthProxy(opts, func(string) bool { return true })
	require.ErrorContains(t, err, "could not validate htpasswd")
	require.FileExists(t, opts.Session.SQLite.Path)
	require.NoFileExists(t, opts.Session.SQLite.Path+"-wal", "failed construction must close the database")
}
