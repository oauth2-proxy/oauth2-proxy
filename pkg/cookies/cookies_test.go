package cookies

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/ip"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Cookie Tests", func() {
	Context("GetCookieDomain", func() {
		type getCookieDomainTableInput struct {
			host           string
			xForwardedHost string
			cookieDomains  []string
			expectedOutput string
		}

		DescribeTable("should return expected results",
			func(in getCookieDomainTableInput) {
				req, err := http.NewRequest(
					http.MethodGet,
					fmt.Sprintf("https://%s/%s", in.host, cookiePath),
					nil,
				)
				Expect(err).ToNot(HaveOccurred())

				if in.xForwardedHost != "" {
					req.Header.Add("X-Forwarded-Host", in.xForwardedHost)
					req.RemoteAddr = "127.0.0.1:4180"
					trustedProxies, err := ip.ParseNetSet([]string{"127.0.0.1"})
					Expect(err).ToNot(HaveOccurred())

					req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{
						ReverseProxy:   true,
						TrustedProxies: trustedProxies,
					})
				}

				Expect(GetCookieDomain(req, in.cookieDomains)).To(Equal(in.expectedOutput))
			},
			Entry("a single exact match for the Host header", getCookieDomainTableInput{
				host:           "www.cookies.test",
				cookieDomains:  []string{"www.cookies.test"},
				expectedOutput: "www.cookies.test",
			}),
			Entry("a single exact match for the X-Forwarded-Host header", getCookieDomainTableInput{
				host:           "backend.cookies.internal",
				xForwardedHost: "www.cookies.test",
				cookieDomains:  []string{"www.cookies.test"},
				expectedOutput: "www.cookies.test",
			}),
			Entry("a single suffix match for the Host header", getCookieDomainTableInput{
				host:           "www.cookies.test",
				cookieDomains:  []string{".cookies.test"},
				expectedOutput: ".cookies.test",
			}),
			Entry("a single suffix match for the X-Forwarded-Host header", getCookieDomainTableInput{
				host:           "backend.cookies.internal",
				xForwardedHost: "www.cookies.test",
				cookieDomains:  []string{".cookies.test"},
				expectedOutput: ".cookies.test",
			}),
			Entry("the first match is used", getCookieDomainTableInput{
				host:           "www.cookies.test",
				cookieDomains:  []string{"www.cookies.test", ".cookies.test"},
				expectedOutput: "www.cookies.test",
			}),
			Entry("the only match is used", getCookieDomainTableInput{
				host:           "www.cookies.test",
				cookieDomains:  []string{".cookies.wrong", ".cookies.test"},
				expectedOutput: ".cookies.test",
			}),
			Entry("blank is returned for no matches", getCookieDomainTableInput{
				host:           "www.cookies.test",
				cookieDomains:  []string{".cookies.wrong", ".cookies.false"},
				expectedOutput: "",
			}),
		)
	})

	Context("MakeCookieFromOptions", func() {
		type makeCookieFromOptionsTableInput struct {
			host           string
			opts           CookieOptions
			now            time.Time
			expectedOutput int
		}

		validName := "_oauth2_proxy"
		domains := []string{"www.cookies.test"}

		now := time.Now()
		var expectedMaxAge int

		DescribeTable("should return cookies with or without expiration",
			func(in makeCookieFromOptionsTableInput) {
				req, err := http.NewRequest(
					http.MethodGet,
					fmt.Sprintf("https://%s/%s", in.host, cookiePath),
					nil,
				)
				Expect(err).ToNot(HaveOccurred())

				Expect(MakeCookieFromOptions(req, &in.opts).MaxAge).To(Equal(in.expectedOutput))
			},
			Entry("persistent cookie", makeCookieFromOptionsTableInput{
				host: "www.cookies.test",
				opts: CookieOptions{
					Name:       validName,
					Value:      "1",
					Domains:    domains,
					Expiration: 15 * time.Minute,
					SameSite:   "",
					Path:       "",
					HTTPOnly:   false,
					Secure:     true,
				},
				now:            now,
				expectedOutput: int((15 * time.Minute).Seconds()),
			}),
			Entry("persistent cookie to be cleared", makeCookieFromOptionsTableInput{
				host: "www.cookies.test",
				opts: CookieOptions{
					Name:       validName,
					Value:      "1",
					Domains:    domains,
					Expiration: time.Hour * -1,
					SameSite:   "",
					Path:       "",
					HTTPOnly:   false,
					Secure:     true,
				},
				now:            now,
				expectedOutput: -1,
			}),
			Entry("session cookie", makeCookieFromOptionsTableInput{
				host: "www.cookies.test",
				opts: CookieOptions{
					Name:       validName,
					Value:      "1",
					Domains:    domains,
					Expiration: 0,
					SameSite:   "",
					Path:       "",
					HTTPOnly:   false,
					Secure:     true,
				},
				now:            now,
				expectedOutput: expectedMaxAge,
			}),
		)

		It("sets the Partitioned attribute and preserves its Set-Cookie order", func() {
			req, err := http.NewRequest(
				http.MethodGet,
				"https://www.cookies.test/"+cookiePath,
				nil,
			)
			Expect(err).ToNot(HaveOccurred())

			cookie := MakeCookieFromOptions(req, &CookieOptions{
				Name:        "_oauth2_proxy",
				Value:       "1",
				Domains:     []string{"www.cookies.test"},
				Expiration:  15 * time.Minute,
				SameSite:    "none",
				Path:        cookiePath,
				HTTPOnly:    true,
				Secure:      true,
				Partitioned: true,
			})

			Expect(cookie.Partitioned).To(BeTrue())

			rw := httptest.NewRecorder()
			http.SetCookie(rw, cookie)
			header := rw.Header().Get("Set-Cookie")
			Expect(header).To(Equal(
				"_oauth2_proxy=1; Path=/cookie-tests; Domain=www.cookies.test; Max-Age=900; HttpOnly; Secure; SameSite=None; Partitioned",
			))

			parsed, err := http.ParseSetCookie(header)
			Expect(err).ToNot(HaveOccurred())
			Expect(parsed.Partitioned).To(BeTrue())
			Expect(parsed.Secure).To(BeTrue())
			Expect(parsed.SameSite).To(Equal(http.SameSiteNoneMode))
		})

		It("does not set the Partitioned attribute by default", func() {
			req, err := http.NewRequest(
				http.MethodGet,
				"https://www.cookies.test/"+cookiePath,
				nil,
			)
			Expect(err).ToNot(HaveOccurred())

			cookie := MakeCookieFromOptions(req, &CookieOptions{
				Name:     "_oauth2_proxy",
				Value:    "1",
				Secure:   true,
				SameSite: "none",
			})

			Expect(cookie.Partitioned).To(BeFalse())
			Expect(cookie.String()).ToNot(ContainSubstring("; Partitioned"))
		})

		It("sets the Partitioned attribute on a deletion cookie", func() {
			req, err := http.NewRequest(
				http.MethodGet,
				"https://www.cookies.test/"+cookiePath,
				nil,
			)
			Expect(err).ToNot(HaveOccurred())

			cookie := MakeCookieFromOptions(req, &CookieOptions{
				Name:        "_oauth2_proxy",
				Domains:     []string{"www.cookies.test"},
				Expiration:  -time.Hour,
				SameSite:    "none",
				Secure:      true,
				Partitioned: true,
			})

			Expect(cookie.MaxAge).To(Equal(-1))
			Expect(cookie.Partitioned).To(BeTrue())
			Expect(cookie.String()).To(ContainSubstring("; Max-Age=0; Secure; SameSite=None; Partitioned"))
		})
	})
})
