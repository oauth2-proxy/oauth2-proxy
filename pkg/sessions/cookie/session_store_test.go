package cookie

import (
	"net/http"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/sessions/tests"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

func TestSessionStore(t *testing.T) {
	logger.SetOutput(GinkgoWriter)
	RegisterFailHandler(Fail)
	RunSpecs(t, "Cookie SessionStore")
}

var _ = Describe("Cookie SessionStore Tests", func() {
	tests.RunSessionStoreTests(
		func(opts *options.SessionOptions, cookieOpts *options.CookieOptions) (sessionsapi.SessionStore, error) {
			// Set the connection URL
			opts.Type = options.CookieSessionStoreType
			return NewCookieSessionStore(opts, cookieOpts)
		}, nil)
})

func Test_copyCookie(t *testing.T) {
	expire, _ := time.Parse(time.RFC3339, "2020-03-17T00:00:00Z")
	c := &http.Cookie{
		Name:       "name",
		Value:      "value",
		Path:       "/path",
		Domain:     "x.y.z",
		Expires:    expire,
		RawExpires: "rawExpire",
		MaxAge:     1,
		Secure:     true,
		HttpOnly:   true,
		Raw:        "raw",
		Unparsed:   []string{"unparsed"},
		SameSite:   http.SameSiteLaxMode,
	}

	got := copyCookie(c)
	assert.Equal(t, c, got)
}
