package cookies

import (
	"net/http"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	csrfState = "1234asdf1234asdf1234asdf"
	csrfNonce = "0987lkjh0987lkjh0987lkjh"

	cookieName   = "cookie_test_12345"
	cookieSecret = "3q48hmFH30FJ2HfJF0239UFJCVcl3kj3"
	cookieDomain = "o2p.cookies.test"
	cookiePath   = "/cookie-tests"

	nowEpoch = 1609366421
)

func TestProviderSuite(t *testing.T) {
	logger.SetOutput(GinkgoWriter)

	RegisterFailHandler(Fail)
	RunSpecs(t, "Cookies")
}

func testCookieExpires(exp time.Time) string {
	var buf [len(http.TimeFormat)]byte
	return string(exp.UTC().AppendFormat(buf[:0], http.TimeFormat))
}
