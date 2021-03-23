package redis

import (
	"context"
	"log"
	"os"
	"testing"
	"time"

	"github.com/Bose/minisentinel"
	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v8"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/cookies"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/persistence"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/tests"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const redisPassword = "0123456789abcdefghijklmnopqrstuv"

// wrappedRedisLogger wraps a logger so that we can coerce the logger to
// fit the expected signature for go-redis logging
type wrappedRedisLogger struct {
	*log.Logger
}

func (l *wrappedRedisLogger) Printf(_ context.Context, format string, v ...interface{}) {
	l.Logger.Printf(format, v...)
}

func TestSessionStore(t *testing.T) {
	logger.SetOutput(GinkgoWriter)
	logger.SetErrOutput(GinkgoWriter)

	redisLogger := &wrappedRedisLogger{Logger: log.New(os.Stderr, "redis: ", log.LstdFlags|log.Lshortfile)}
	redisLogger.SetOutput(GinkgoWriter)
	redis.SetLogger(redisLogger)

	RegisterFailHandler(Fail)
	RunSpecs(t, "Redis SessionStore")
}

var _ = Describe("Redis SessionStore Tests", func() {
	// helper interface to allow us to close client connections
	// All non-nil redis clients should implement this
	type closer interface {
		Close() error
	}

	var mr *miniredis.Miniredis
	var ss sessionsapi.SessionStore

	BeforeEach(func() {
		var err error
		mr, err = miniredis.Run()
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		mr.Close()
	})

	JustAfterEach(func() {
		// Release any connections immediately after the test ends
		if redisManager, ok := ss.(*persistence.Manager); ok {
			if redisManager.Store.(*SessionStore).Client != nil {
				Expect(redisManager.Store.(*SessionStore).Client.(closer).Close()).To(Succeed())
			}
		}
	})

	tests.RunSessionStoreTests(
		func(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
			// Set the connection URL
			opts.Type = options.RedisSessionStoreType
			opts.Redis.ConnectionURL = "redis://" + mr.Addr()

			// Capture the session store so that we can close the client
			var err error
			ss, err = NewRedisSessionStore(opts, cookies.NewBuilder(*cookieOpts))
			return ss, err
		},
		func(d time.Duration) error {
			mr.FastForward(d)
			return nil
		},
	)

	Context("with sentinel", func() {
		var ms *minisentinel.Sentinel

		BeforeEach(func() {
			ms = minisentinel.NewSentinel(mr)
			Expect(ms.Start()).To(Succeed())
		})

		AfterEach(func() {
			ms.Close()
		})

		tests.RunSessionStoreTests(
			func(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
				// Set the sentinel connection URL
				sentinelAddr := "redis://" + ms.Addr()
				opts.Type = options.RedisSessionStoreType
				opts.Redis.SentinelConnectionURLs = []string{sentinelAddr}
				opts.Redis.UseSentinel = true
				opts.Redis.SentinelMasterName = ms.MasterInfo().Name

				// Capture the session store so that we can close the client
				var err error
				ss, err = NewRedisSessionStore(opts, cookies.NewBuilder(*cookieOpts))
				return ss, err
			},
			func(d time.Duration) error {
				mr.FastForward(d)
				return nil
			},
		)
	})

	Context("with cluster", func() {
		tests.RunSessionStoreTests(
			func(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
				clusterAddr := "redis://" + mr.Addr()
				opts.Type = options.RedisSessionStoreType
				opts.Redis.ClusterConnectionURLs = []string{clusterAddr}
				opts.Redis.UseCluster = true

				// Capture the session store so that we can close the client
				var err error
				ss, err = NewRedisSessionStore(opts, cookies.NewBuilder(*cookieOpts))
				return ss, err
			},
			func(d time.Duration) error {
				mr.FastForward(d)
				return nil
			},
		)
	})

	Context("with a redis password", func() {
		BeforeEach(func() {
			mr.RequireAuth(redisPassword)
		})

		AfterEach(func() {
			mr.RequireAuth("")
		})

		tests.RunSessionStoreTests(
			func(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
				// Set the connection URL
				opts.Type = options.RedisSessionStoreType
				opts.Redis.ConnectionURL = "redis://" + mr.Addr()
				opts.Redis.Password = redisPassword

				// Capture the session store so that we can close the client
				var err error
				ss, err = NewRedisSessionStore(opts, cookies.NewBuilder(*cookieOpts))
				return ss, err
			},
			func(d time.Duration) error {
				mr.FastForward(d)
				return nil
			},
		)

		Context("with sentinel", func() {
			var ms *minisentinel.Sentinel

			BeforeEach(func() {
				ms = minisentinel.NewSentinel(mr)
				Expect(ms.Start()).To(Succeed())
			})

			AfterEach(func() {
				ms.Close()
			})

			tests.RunSessionStoreTests(
				func(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
					// Set the sentinel connection URL
					sentinelAddr := "redis://" + ms.Addr()
					opts.Type = options.RedisSessionStoreType
					opts.Redis.SentinelConnectionURLs = []string{sentinelAddr}
					opts.Redis.UseSentinel = true
					opts.Redis.SentinelMasterName = ms.MasterInfo().Name
					opts.Redis.Password = redisPassword

					// Capture the session store so that we can close the client
					var err error
					ss, err = NewRedisSessionStore(opts, cookies.NewBuilder(*cookieOpts))
					return ss, err
				},
				func(d time.Duration) error {
					mr.FastForward(d)
					return nil
				},
			)
		})

		Context("with cluster", func() {
			tests.RunSessionStoreTests(
				func(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
					clusterAddr := "redis://" + mr.Addr()
					opts.Type = options.RedisSessionStoreType
					opts.Redis.ClusterConnectionURLs = []string{clusterAddr}
					opts.Redis.UseCluster = true
					opts.Redis.Password = redisPassword

					// Capture the session store so that we can close the client
					var err error
					ss, err = NewRedisSessionStore(opts, cookies.NewBuilder(*cookieOpts))
					return ss, err
				},
				func(d time.Duration) error {
					mr.FastForward(d)
					return nil
				},
			)
		})
	})
})
