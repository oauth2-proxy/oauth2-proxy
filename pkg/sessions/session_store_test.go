package sessions_test

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions"
	sessionscookie "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/cookie"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/persistence"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions/redis"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSessionStore(t *testing.T) {
	logger.SetOutput(GinkgoWriter)
	logger.SetErrOutput(GinkgoWriter)

	RegisterFailHandler(Fail)
	RunSpecs(t, "SessionStore")
}

var _ = Describe("NewSessionStore", func() {
	var opts *options.SessionOptions
	var cookieOpts *options.Cookie

	BeforeEach(func() {
		opts = &options.SessionOptions{}

		// A secret is required to create a Cipher, validation ensures it is the correct
		// length before a session store is initialised.
		secret := make([]byte, 32)
		_, err := rand.Read(secret)
		Expect(err).ToNot(HaveOccurred())

		// Set default options in CookieOptions
		cookieOpts = &options.Cookie{
			Name:     "_oauth2_proxy",
			Secret:   base64.URLEncoding.EncodeToString(secret),
			Path:     "/",
			Expire:   time.Duration(168) * time.Hour,
			Refresh:  time.Duration(1) * time.Hour,
			Secure:   true,
			HTTPOnly: true,
			SameSite: "",
		}
	})

	Context("with type 'cookie'", func() {
		BeforeEach(func() {
			opts.Type = options.CookieSessionStoreType
		})

		It("creates a cookie.SessionStore", func() {
			ss, err := sessions.NewSessionStore(opts, cookieOpts)
			Expect(err).NotTo(HaveOccurred())
			Expect(ss).To(BeAssignableToTypeOf(&sessionscookie.SessionStore{}))
		})
	})

	Context("with type 'redis'", func() {
		BeforeEach(func() {
			opts.Type = options.RedisSessionStoreType
			opts.Redis.ConnectionURL = "redis://"
		})

		It("creates a persistence.Manager that wraps a redis.SessionStore", func() {
			ss, err := sessions.NewSessionStore(opts, cookieOpts)
			Expect(err).NotTo(HaveOccurred())
			Expect(ss).To(BeAssignableToTypeOf(&persistence.Manager{}))
			Expect(ss.(*persistence.Manager).Store).To(BeAssignableToTypeOf(&redis.SessionStore{}))
		})
	})

	Context("with an invalid type", func() {
		BeforeEach(func() {
			opts.Type = "invalid-type"
		})

		It("returns an error", func() {
			ss, err := sessions.NewSessionStore(opts, cookieOpts)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(Equal("unknown session store type 'invalid-type'"))
			Expect(ss).To(BeNil())
		})
	})
})
