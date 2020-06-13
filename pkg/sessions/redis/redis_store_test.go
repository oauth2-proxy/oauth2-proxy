package redis

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Bose/minisentinel"
	"github.com/alicebob/miniredis/v2"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedisStore(t *testing.T) {
	t.Run("save session on redis standalone", func(t *testing.T) {
		redisServer, err := miniredis.Run()
		require.NoError(t, err)
		defer redisServer.Close()

		opts := options.NewOptions()
		redisURL := url.URL{
			Scheme: "redis",
			Host:   redisServer.Addr(),
		}
		opts.Session.Redis.ConnectionURL = redisURL.String()
		redisStore, err := NewRedisSessionStore(&opts.Session, &opts.Cookie)
		require.NoError(t, err)

		recorder := httptest.NewRecorder()
		err = redisStore.Save(
			recorder,
			httptest.NewRequest(http.MethodGet, "/", nil),
			&sessions.SessionState{})
		assert.NoError(t, err)
		cookies := recorder.Result().Cookies()
		assert.Len(t, cookies, 1)
		assert.Equal(t, cookies[0].Name, opts.Cookie.Name)
	})

	t.Run("load session on empty redis standalone fails", func(t *testing.T) {
		redisServer, err := miniredis.Run()
		require.NoError(t, err)
		defer redisServer.Close()

		opts := options.NewOptions()
		redisURL := url.URL{
			Scheme: "redis",
			Host:   redisServer.Addr(),
		}
		opts.Session.Redis.ConnectionURL = redisURL.String()
		redisStore, err := NewRedisSessionStore(&opts.Session, &opts.Cookie)
		require.NoError(t, err)

		sessionState, err := redisStore.Load(
			httptest.NewRequest(http.MethodGet, "/", nil),
		)
		assert.Nil(t, sessionState)
		assert.Error(t, err, "error loading session")
	})

	t.Run("save+load session on redis standalone success", func(t *testing.T) {
		redisServer, err := miniredis.Run()
		require.NoError(t, err)
		defer redisServer.Close()

		opts := options.NewOptions()
		redisURL := url.URL{
			Scheme: "redis",
			Host:   redisServer.Addr(),
		}
		opts.Session.Redis.ConnectionURL = redisURL.String()
		redisStore, err := NewRedisSessionStore(&opts.Session, &opts.Cookie)
		require.NoError(t, err)

		recorder := httptest.NewRecorder()
		prevSessionState := &sessions.SessionState{}
		err = redisStore.Save(
			recorder,
			httptest.NewRequest(http.MethodGet, "/", nil),
			prevSessionState)
		assert.NoError(t, err)
		cookies := recorder.Result().Cookies()
		assert.Len(t, cookies, 1)
		assert.Equal(t, cookies[0].Name, opts.Cookie.Name)

		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(cookies[0])
		sessionState, err := redisStore.Load(request)
		assert.NoError(t, err)
		assert.Equal(t, prevSessionState.Email, sessionState.Email)
	})

	t.Run("save+load+clear+load session on redis standalone success", func(t *testing.T) {
		redisServer, err := miniredis.Run()
		require.NoError(t, err)
		defer redisServer.Close()

		opts := options.NewOptions()
		redisURL := url.URL{
			Scheme: "redis",
			Host:   redisServer.Addr(),
		}
		opts.Session.Redis.ConnectionURL = redisURL.String()
		redisStore, err := NewRedisSessionStore(&opts.Session, &opts.Cookie)
		require.NoError(t, err)

		recorder := httptest.NewRecorder()
		prevSessionState := &sessions.SessionState{}
		err = redisStore.Save(
			recorder,
			httptest.NewRequest(http.MethodGet, "/", nil),
			prevSessionState)
		assert.NoError(t, err)
		cookies := recorder.Result().Cookies()
		assert.Len(t, cookies, 1)
		assert.Equal(t, cookies[0].Name, opts.Cookie.Name)

		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.AddCookie(cookies[0])
		sessionState, err := redisStore.Load(request)
		assert.NoError(t, err)
		assert.Equal(t, prevSessionState.Email, sessionState.Email)

		err = redisStore.Clear(recorder, request)
		assert.NoError(t, err)

		request.AddCookie(cookies[0])
		sessionState, err = redisStore.Load(request)
		assert.Nil(t, sessionState)
		assert.Error(t, err, "retrieving from store")
	})

	t.Run("save session on redis sentinel", func(t *testing.T) {
		redisServer, err := miniredis.Run()
		require.NoError(t, err)
		defer redisServer.Close()
		sentinel := minisentinel.NewSentinel(redisServer)
		err = sentinel.Start()
		require.NoError(t, err)
		defer sentinel.Close()
		opts := options.NewOptions()
		sentinelURL := url.URL{
			Scheme: "redis",
			Host:   sentinel.Addr(),
		}
		opts.Session.Redis.SentinelConnectionURLs = []string{sentinelURL.String()}
		opts.Session.Redis.UseSentinel = true
		opts.Session.Redis.SentinelMasterName = sentinel.MasterInfo().Name
		redisStore, err := NewRedisSessionStore(&opts.Session, &opts.Cookie)
		require.NoError(t, err)
		err = redisStore.Save(
			httptest.NewRecorder(),
			httptest.NewRequest(http.MethodGet, "/", nil),
			&sessions.SessionState{})
		assert.NoError(t, err)
	})
}
