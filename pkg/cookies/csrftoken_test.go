package cookies

import (
	"fmt"
	"net/http"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CSRF Token Cookie Tests", func() {
	Context("MakeCSRFTokenCookieFromOptions", func() {
		type makeCSRFTokenCookieFromOptionsTableInput struct {
			host           string
			name           string
			value          string
			opts           options.CSRFToken
			expiration     time.Duration
			now            time.Time
			expectedOutput time.Time
		}

		validName := "_oauth2_proxy_csrftoken"
		domains := []string{"www.cookies.test"}

		now := time.Now()
		var expectedExpires time.Time

		DescribeTable("should return cookies with or without expiration",
			func(in makeCSRFTokenCookieFromOptionsTableInput) {
				req, err := http.NewRequest(
					http.MethodGet,
					fmt.Sprintf("https://%s/%s", in.host, cookiePath),
					nil,
				)
				Expect(err).ToNot(HaveOccurred())

				Expect(MakeCSRFTokenCookieFromOptions(req, in.name, in.value, &in.opts, in.expiration, in.now).Expires).To(Equal(in.expectedOutput))
			},
			Entry("persistent cookie", makeCSRFTokenCookieFromOptionsTableInput{
				host:           "www.cookies.test",
				name:           validName,
				value:          "1",
				opts:           options.CSRFTokenDefaults(),
				expiration:     15 * time.Minute,
				now:            now,
				expectedOutput: now.Add(15 * time.Minute),
			}),
			Entry("session cookie", makeCSRFTokenCookieFromOptionsTableInput{
				host:  "www.cookies.test",
				name:  validName,
				value: "1",
				opts: options.CSRFToken{
					CookieName:     validName,
					CookieDomains:  domains,
					CookiePath:     "",
					CookieExpire:   0,
					CookieSecure:   true,
					CookieHTTPOnly: false,
					CookieSameSite: "",
				},
				expiration:     0,
				now:            now,
				expectedOutput: expectedExpires,
			}),
		)
	})
})
