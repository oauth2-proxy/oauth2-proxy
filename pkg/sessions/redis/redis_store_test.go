package redis_test

import (
	"crypto/aes"
	"crypto/rand"
	"io"
	"log"
	"os"
	"testing"
	"time"

	"github.com/Bose/minisentinel"
	"github.com/alicebob/miniredis/v2"
	"github.com/go-redis/redis/v7"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	redissession "github.com/oauth2-proxy/oauth2-proxy/pkg/sessions/redis"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/sessions/tests"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

func TestLegacyV5DecodeSession(t *testing.T) {
	testCases, _, legacyCipher := tests.CreateLegacyV5TestCases(t)

	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			secret := make([]byte, aes.BlockSize)
			_, err := io.ReadFull(rand.Reader, secret)
			assert.NoError(t, err)
			ticket := &redissession.TicketData{
				TicketID: "",
				Secret:   secret,
			}

			encrypted, err := tests.LegacyStoreValue(tc.Input, ticket)
			assert.NoError(t, err)

			ss, err := redissession.LegacyV5DecodeSession(encrypted, ticket, legacyCipher)
			if tc.Error {
				assert.Error(t, err)
				assert.Nil(t, ss)
				return
			}
			assert.NoError(t, err)

			// Compare sessions without *time.Time fields
			exp := *tc.Output
			exp.CreatedAt = nil
			exp.ExpiresOn = nil
			act := *ss
			act.CreatedAt = nil
			act.ExpiresOn = nil
			assert.Equal(t, exp, act)
		})
	}
}

func TestSessionStore(t *testing.T) {
	logger.SetOutput(GinkgoWriter)

	redisLogger := log.New(os.Stderr, "redis: ", log.LstdFlags|log.Lshortfile)
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
		if redisStore, ok := ss.(*redissession.SessionStore); ok {
			if redisStore.Client != nil {
				Expect(redisStore.Client.(closer).Close()).To(Succeed())
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
			ss, err = redissession.NewRedisSessionStore(opts, cookieOpts)
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
				ss, err = redissession.NewRedisSessionStore(opts, cookieOpts)
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
				ss, err = redissession.NewRedisSessionStore(opts, cookieOpts)
				return ss, err
			},
			func(d time.Duration) error {
				mr.FastForward(d)
				return nil
			},
		)
	})
})
