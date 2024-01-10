package redis

import (
	"bytes"
	"crypto/tls"
	"encoding/pem"
	"os"
	"time"

	"github.com/Bose/minisentinel"
	"github.com/alicebob/miniredis/v2"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/persistence"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/tests"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const redisUsername = "testuser"
const redisPassword = "0123456789abcdefghijklmnopqrstuv"

var (
	cert   tls.Certificate
	caPath string
)

var _ = BeforeSuite(func() {
	var err error
	certBytes, keyBytes, err := util.GenerateCert("127.0.0.1")
	Expect(err).ToNot(HaveOccurred())
	certOut := new(bytes.Buffer)
	Expect(pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})).To(Succeed())
	certData := certOut.Bytes()
	keyOut := new(bytes.Buffer)
	Expect(pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})).To(Succeed())
	cert, err = tls.X509KeyPair(certData, keyOut.Bytes())
	Expect(err).ToNot(HaveOccurred())

	certFile, err := os.CreateTemp("", "cert.*.pem")
	Expect(err).ToNot(HaveOccurred())
	caPath = certFile.Name()
	_, err = certFile.Write(certData)
	defer certFile.Close()
	Expect(err).ToNot(HaveOccurred())
})

var _ = AfterSuite(func() {
	Expect(os.Remove(caPath)).ToNot(HaveOccurred())
})

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
				clusterAddr := "redis://" + mr.Addr()
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
				opts.Redis.ConnectionURL = "redis://" + mr.Addr()
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
					clusterAddr := "redis://" + mr.Addr()
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

	Context("with TLS connection", func() {
		BeforeEach(func() {
			mr.Close()

			var err error
			mr, err = miniredis.RunTLS(&tls.Config{Certificates: []tls.Certificate{cert}})
			Expect(err).ToNot(HaveOccurred())
		})
		AfterEach(func() {
			mr.Close()

			var err error
			mr, err = miniredis.Run()
			Expect(err).ToNot(HaveOccurred())
		})

		Context("with standalone", func() {
			tests.RunSessionStoreTests(
				func(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
					// Set the connection URL
					opts.Type = options.RedisSessionStoreType
					opts.Redis.ConnectionURL = "rediss://" + mr.Addr()
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
					clusterAddr := "rediss://" + mr.Addr()
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
		BeforeEach(func() {
			mr.Close()

			var err error
			mr, err = miniredis.RunTLS(&tls.Config{Certificates: []tls.Certificate{cert}})
			Expect(err).ToNot(HaveOccurred())
		})
		AfterEach(func() {
			mr.Close()

			var err error
			mr, err = miniredis.Run()
			Expect(err).ToNot(HaveOccurred())
		})

		Context("with standalone", func() {
			tests.RunSessionStoreTests(
				func(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
					// Set the connection URL
					opts.Type = options.RedisSessionStoreType
					opts.Redis.ConnectionURL = "rediss://" + mr.Addr()
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
					clusterAddr := "rediss://" + mr.Addr()
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
		BeforeEach(func() {
			mr.Close()

			var err error
			mr, err = miniredis.RunTLS(&tls.Config{Certificates: []tls.Certificate{cert}})
			Expect(err).ToNot(HaveOccurred())
		})

		AfterEach(func() {
			mr.Close()

			var err error
			mr, err = miniredis.Run()
			Expect(err).ToNot(HaveOccurred())
		})

		tests.RunSessionStoreTests(
			func(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessionsapi.SessionStore, error) {
				// Set the connection URL
				opts.Type = options.RedisSessionStoreType
				opts.Redis.ConnectionURL = "redis://" + mr.Addr()
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
		BeforeEach(func() {
			mr.Close()

			var err error
			mr, err = miniredis.RunTLS(&tls.Config{Certificates: []tls.Certificate{cert}})
			Expect(err).ToNot(HaveOccurred())
		})

		AfterEach(func() {
			mr.Close()

			var err error
			mr, err = miniredis.Run()
			Expect(err).ToNot(HaveOccurred())
		})

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
