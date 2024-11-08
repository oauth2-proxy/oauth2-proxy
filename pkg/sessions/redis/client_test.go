package redis_test

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/redis"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Redis Client Tests", func() {
	Context("with basic client", func() {
		RunClientTests(func(mr *miniredis.Miniredis) options.RedisStoreOptions {
			return options.RedisStoreOptions{
				ConnectionURL: "redis://" + mr.Addr(),
			}
		})
	})

	Context("with cluster client", func() {
		RunClientTests(func(mr *miniredis.Miniredis) options.RedisStoreOptions {
			return options.RedisStoreOptions{
				ClusterConnectionURLs: []string{"redis://" + mr.Addr()},
				UseCluster:            true,
			}
		})
	})
})

type getOptsFunc func(mr *miniredis.Miniredis) options.RedisStoreOptions

func RunClientTests(getOptsFunc getOptsFunc) {
	var mr *miniredis.Miniredis
	var client redis.Client
	var err error
	var key string
	var ctx context.Context

	BeforeEach(func() {
		mr, err = miniredis.Run()
		Expect(err).ToNot(HaveOccurred())

		client, err = redis.NewRedisClient(getOptsFunc(mr))
		Expect(err).ToNot(HaveOccurred())

		nonce, err := encryption.Nonce(32)
		Expect(err).ToNot(HaveOccurred())
		key = base64.RawURLEncoding.EncodeToString(nonce)

		ctx = context.Background()
	})

	AfterEach(func() {
		if mr != nil {
			mr.Close()
			mr = nil
		}
	})

	Context("when Get is called", func() {
		expectedValue := []byte("value")

		BeforeEach(func() {
			client.Set(context.Background(), key, expectedValue, time.Duration(1*time.Minute))
		})

		It("returns the saved value", func() {
			value, err := client.Get(ctx, key)
			Expect(err).ToNot(HaveOccurred())
			Expect(value).To(Equal(value))
		})

		It("does not return expired values", func() {
			mr.FastForward(5 * time.Minute)

			_, err = client.Get(ctx, key)
			Expect(err).To(HaveOccurred())
		})

		It("returns an error if value does not exist", func() {
			_, err = client.Get(ctx, "does-not-exists")
			Expect(err).To(HaveOccurred())
		})
	})

	Context("using Lock", func() {
		It("maintains the lock", func() {
			lock := client.Lock(key)

			err = lock.Obtain(ctx, 1*time.Minute)
			Expect(err).ToNot(HaveOccurred())

			isLocked, err := lock.Peek(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(isLocked).To(BeTrue())

			err = lock.Release(ctx)
			Expect(err).ToNot(HaveOccurred())
		})

		It("reflects non-locked instance", func() {
			lock := client.Lock(key)

			isLocked, err := lock.Peek(ctx)
			Expect(err).ToNot(HaveOccurred())
			Expect(isLocked).To(BeFalse())
		})
	})

	Context("when Set is called", func() {
		expectedValue := []byte("value")

		It("sets the expected value", func() {
			err = client.Set(ctx, key, expectedValue, 1*time.Minute)
			Expect(err).ToNot(HaveOccurred())

			value, err := client.Get(ctx, key)
			Expect(value).To(Equal(expectedValue))
			Expect(err).ToNot(HaveOccurred())
		})
	})

	Context("when Del is called", func() {
		It("does not return an error when key exists", func() {
			err = client.Set(ctx, key, []byte("dummy"), 1*time.Minute)
			Expect(err).ToNot(HaveOccurred())

			err = client.Del(ctx, key)
			Expect(err).ToNot(HaveOccurred())

			_, err = client.Get(ctx, key)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("when Ping is called", func() {
		Context("when redis is up", func() {
			It("does not return an error", func() {
				err = client.Ping(ctx)
				Expect(err).ToNot(HaveOccurred())
			})
		})

		Context("when redis is down", func() {
			It("returns an error", func() {
				mr.Close()
				mr = nil

				err = client.Ping(ctx)
				Expect(err).To(HaveOccurred())
			})
		})
	})
}
