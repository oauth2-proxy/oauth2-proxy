package cookies

import (
	"fmt"
	"net/http"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
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
					req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{
						ReverseProxy: true,
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
})
