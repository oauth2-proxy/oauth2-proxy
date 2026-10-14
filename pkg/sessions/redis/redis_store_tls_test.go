package redis

import (
	"crypto/tls"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/persistence"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/tests"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

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
		mr, err = miniredis.RunTLS(&tls.Config{Certificates: []tls.Certificate{cert}})
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

	const redissProtocol = "rediss://"
	Context("with TLS connection", func() {
		Context("with standalone", func() {
			tests.RunSessionStoreTests(
				func(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
					// Set the connection URL
					opts.Type = options.RedisSessionStoreType
					opts.Redis.ConnectionURL = redissProtocol + mr.Addr()
					opts.Redis.CAPath = caPath

					// Capture the session store so that we can close the client
					ss, err := NewRedisSessionStore(opts, cookieOpts)
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
					clusterAddr := redissProtocol + mr.Addr()
					opts.Type = options.RedisSessionStoreType
					opts.Redis.ClusterConnectionURLs = []string{clusterAddr}
					opts.Redis.UseCluster = true
					opts.Redis.CAPath = caPath

					// Capture the session store so that we can close the client
					var err error
					ss, err = NewRedisSessionStore(opts, cookieOpts)
					return ss, err
				},
				func(d time.Duration) error {
					mr.FastForward(d)
					return nil
				},
			)
		})
	})

	Context("with insecure TLS connection", func() {
		Context("with standalone", func() {
			tests.RunSessionStoreTests(
				func(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
					// Set the connection URL
					opts.Type = options.RedisSessionStoreType
					opts.Redis.ConnectionURL = redissProtocol + mr.Addr()
					opts.Redis.InsecureSkipTLSVerify = true

					// Capture the session store so that we can close the client
					ss, err := NewRedisSessionStore(opts, cookieOpts)
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
					clusterAddr := redissProtocol + mr.Addr()
					opts.Type = options.RedisSessionStoreType
					opts.Redis.ClusterConnectionURLs = []string{clusterAddr}
					opts.Redis.UseCluster = true
					opts.Redis.InsecureSkipTLSVerify = true

					// Capture the session store so that we can close the client
					var err error
					ss, err = NewRedisSessionStore(opts, cookieOpts)
					return ss, err
				},
				func(d time.Duration) error {
					mr.FastForward(d)
					return nil
				},
			)
		})
	})

	Context("with custom CA path", func() {
		tests.RunSessionStoreTests(
			func(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
				// Set the connection URL
				opts.Type = options.RedisSessionStoreType
				opts.Redis.ConnectionURL = redissProtocol + mr.Addr()
				opts.Redis.CAPath = caPath

				// Capture the session store so that we can close the client
				var err error
				ss, err = NewRedisSessionStore(opts, cookieOpts)
				return ss, err
			},
			func(d time.Duration) error {
				mr.FastForward(d)
				return nil
			},
		)
	})

	Context("with insecure TLS connection", func() {
		tests.RunSessionStoreTests(
			func(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
				// Set the connection URL
				opts.Type = options.RedisSessionStoreType
				opts.Redis.ConnectionURL = "redis://127.0.0.1:" + mr.Port() // func (*Miniredis) StartTLS listens on 127.0.0.1
				opts.Redis.InsecureSkipTLSVerify = true

				// Capture the session store so that we can close the client
				var err error
				ss, err = NewRedisSessionStore(opts, cookieOpts)
				return ss, err
			},
			func(d time.Duration) error {
				mr.FastForward(d)
				return nil
			},
		)
	})
})
