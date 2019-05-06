package sessions_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/pusher/oauth2_proxy/pkg/apis/options"
	"github.com/pusher/oauth2_proxy/pkg/sessions"
	"github.com/pusher/oauth2_proxy/pkg/sessions/cookie"
)

func TestSessionStore(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "SessionStore")
}

var _ = Describe("NewSessionStore", func() {
	var opts *options.SessionOptions
	var cookieOpts *options.CookieOptions

	BeforeEach(func() {
		opts = &options.SessionOptions{}
		cookieOpts = &options.CookieOptions{}
	})

	Context("with type 'cookie'", func() {
		BeforeEach(func() {
			opts.Type = options.CookieSessionStoreType
		})

		It("creates a CookieSessionStore", func() {
			ss, err := sessions.NewSessionStore(opts, cookieOpts)
			Expect(err).NotTo(HaveOccurred())
			Expect(ss).To(BeAssignableToTypeOf(&cookie.SessionStore{}))
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
