package redis

import (
	"fmt"
	"time"

	"github.com/Bose/minisentinel"
	"github.com/alicebob/miniredis/v2"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/persistence"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/tests"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	redisUsername = "testuser"
	redisPassword = "0123456789abcdefghijklmnopqrstuv"
)

var _ = Describe("Redis SessionStore Tests", func() {
	Describe("Redis SessionStore Creation", func() {
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

		const redisProtocol = "redis://"
		tests.RunSessionStoreTests(
			func(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
				// Set the connection URL
				opts.Type = options.RedisSessionStoreType
				opts.Redis.ConnectionURL = redisProtocol + mr.Addr()

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

		Context("with sentinel", func() {
			var ms *minisentinel.Sentinel

			BeforeEach(func() {
				ms = minisentinel.NewSentinel(mr)
				Expect(ms.Start()).To(Succeed())
			})

			tests.RunSessionStoreTests(
				func(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
					// Set the sentinel connection URL
					sentinelAddr := redisProtocol + ms.Addr()
					opts.Type = options.RedisSessionStoreType
					opts.Redis.SentinelConnectionURLs = []string{sentinelAddr}
					opts.Redis.UseSentinel = true
					opts.Redis.SentinelMasterName = ms.MasterInfo().Name

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

		Context("with cluster", func() {
			tests.RunSessionStoreTests(
				func(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
					clusterAddr := redisProtocol + mr.Addr()
					opts.Type = options.RedisSessionStoreType
					opts.Redis.ClusterConnectionURLs = []string{clusterAddr}
					opts.Redis.UseCluster = true

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
					opts.Redis.ConnectionURL = redisProtocol + mr.Addr()
					opts.Redis.Password = redisPassword

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

			Context("with sentinel", func() {
				var ms *minisentinel.Sentinel

				BeforeEach(func() {
					ms = minisentinel.NewSentinel(mr)
					Expect(ms.Start()).To(Succeed())
				})

				tests.RunSessionStoreTests(
					func(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
						// Set the sentinel connection URL
						sentinelAddr := redisProtocol + ms.Addr()
						opts.Type = options.RedisSessionStoreType
						opts.Redis.SentinelConnectionURLs = []string{sentinelAddr}
						opts.Redis.UseSentinel = true
						opts.Redis.SentinelMasterName = ms.MasterInfo().Name
						opts.Redis.Password = redisPassword

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

			Context("with cluster", func() {
				tests.RunSessionStoreTests(
					func(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
						clusterAddr := redisProtocol + mr.Addr()
						opts.Type = options.RedisSessionStoreType
						opts.Redis.ClusterConnectionURLs = []string{clusterAddr}
						opts.Redis.UseCluster = true
						opts.Redis.Password = redisPassword

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

		Context("with a redis username and password", func() {
			BeforeEach(func() {
				mr.RequireUserAuth(redisUsername, redisPassword)
			})

			AfterEach(func() {
				mr.RequireUserAuth("", "")
			})

			tests.RunSessionStoreTests(
				func(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
					// Set the connection URL
					opts.Type = options.RedisSessionStoreType
					opts.Redis.ConnectionURL = "redis://" + redisUsername + "@" + mr.Addr()
					opts.Redis.Password = redisPassword

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

			Context("with cluster", func() {
				tests.RunSessionStoreTests(
					func(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
						clusterAddr := "redis://" + redisUsername + "@" + mr.Addr()
						opts.Type = options.RedisSessionStoreType
						opts.Redis.ClusterConnectionURLs = []string{clusterAddr}
						opts.Redis.UseCluster = true
						opts.Redis.Username = redisUsername
						opts.Redis.Password = redisPassword

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
	})

	Describe("Redis URL Parsing", func() {
		It("should prefer configured username password and timeout over URL parameters", func() {
			configuredUsername := "configured-user"
			configuredPassword := "configured-password"
			configuredIdleTimeout := 90

			urlUsername := "url-user"
			urlPassword := "url-password"
			urlIdleTimeout := 30

			redisClient, err := buildStandaloneClient(options.RedisStoreOptions{
				ConnectionURL: fmt.Sprintf("redis://%s:%s@localhost:6379?conn_max_idle_time=%d", urlUsername, urlPassword, urlIdleTimeout),
				Username:      configuredUsername,
				Password:      configuredPassword,
				IdleTimeout:   configuredIdleTimeout,
			})
			Expect(err).ToNot(HaveOccurred())

			rc, ok := redisClient.(*client)
			Expect(ok).To(BeTrue())
			Expect(rc.Close()).To(Succeed())

			redisOptions := rc.Options()
			Expect(redisOptions.Username).To(Equal(configuredUsername))
			Expect(redisOptions.Password).To(Equal(configuredPassword))
			Expect(redisOptions.ConnMaxIdleTime).To(Equal(time.Duration(configuredIdleTimeout) * time.Second))
		})
		It("should prefer URL username password and timeout when configured values are empty", func() {
			urlUsername := "url-user"
			urlPassword := "url-password"
			urlIdleTimeout := 30

			redisClient, err := buildStandaloneClient(options.RedisStoreOptions{
				ConnectionURL: fmt.Sprintf("redis://%s:%s@localhost:6379?conn_max_idle_time=%d", urlUsername, urlPassword, urlIdleTimeout),
				Username:      "",
				Password:      "",
				IdleTimeout:   0,
			})
			Expect(err).ToNot(HaveOccurred())

			rc, ok := redisClient.(*client)
			Expect(ok).To(BeTrue())
			Expect(rc.Close()).To(Succeed())

			redisOptions := rc.Options()
			Expect(redisOptions.Username).To(Equal(urlUsername))
			Expect(redisOptions.Password).To(Equal(urlPassword))
			Expect(redisOptions.ConnMaxIdleTime).To(Equal(time.Duration(urlIdleTimeout) * time.Second))
		})

		It("should parse valid redis URL", func() {
			addrs, opts, err := parseRedisURLs([]string{"redis://localhost:6379"})
			Expect(err).ToNot(HaveOccurred())
			Expect(addrs).To(Equal([]string{"localhost:6379"}))
			Expect(opts).ToNot(BeNil())
			Expect(opts.Addr).To(Equal("localhost:6379"))
		})

		It("should return error for invalid redis URL", func() {
			addrs, opts, err := parseRedisURLs([]string{"invalid://url"})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("unable to parse redis url"))
			Expect(err.Error()).To(Not(ContainSubstring("no redis urls provided")))
			Expect(addrs).To(BeNil())
			Expect(opts).To(BeNil())
		})

		It("should return error when no URLs provided", func() {
			addrs, opts, err := parseRedisURLs([]string{})
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("unable to parse redis urls: no redis urls provided"))
			Expect(addrs).To(BeNil())
			Expect(opts).To(BeNil())
		})
	})
})
