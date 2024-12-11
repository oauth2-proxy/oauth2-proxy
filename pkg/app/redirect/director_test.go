package redirect

import (
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const testProxyPrefix = "/oauth2"

var _ = Describe("Director Suite", func() {
	type getRedirectTableInput struct {
		requestURL       string
		headers          map[string]string
		reverseProxy     bool
		validator        Validator
		expectedRedirect string
	}

	const fooBar = "/foo/bar"
	DescribeTable("GetRedirect",
		func(in getRedirectTableInput) {
			appDirector := NewAppDirector(AppDirectorOpts{
				ProxyPrefix: testProxyPrefix,
				Validator:   in.validator,
			})

			req, _ := http.NewRequest("GET", in.requestURL, nil)
			for header, value := range in.headers {
				if value != "" {
					req.Header.Add(header, value)
				}
			}
			req = middleware.AddRequestScope(req, &middleware.RequestScope{
				ReverseProxy: in.reverseProxy,
			})

			redirect, err := appDirector.GetRedirect(req)
			Expect(err).ToNot(HaveOccurred())
			Expect(redirect).To(Equal(in.expectedRedirect))
		},
		Entry("Request outside of the proxy prefix, redirects to original request", getRedirectTableInput{
			requestURL:       fooBar,
			headers:          nil,
			reverseProxy:     false,
			validator:        testValidator(true),
			expectedRedirect: fooBar,
		}),
		Entry("Request with query, preserves the query", getRedirectTableInput{
			requestURL:       "/foo?bar",
			headers:          nil,
			reverseProxy:     false,
			validator:        testValidator(true),
			expectedRedirect: "/foo?bar",
		}),
		Entry("Request under the proxy prefix, redirects to root", getRedirectTableInput{
			requestURL:       testProxyPrefix + fooBar,
			headers:          nil,
			reverseProxy:     false,
			validator:        testValidator(true),
			expectedRedirect: "/",
		}),
		Entry("Proxied request with headers, outside of ProxyPrefix, redirects to proxied URL", getRedirectTableInput{
			requestURL: "https://oauth.example.com/foo/bar",
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "a-service.example.com",
				"X-Forwarded-Uri":   fooBar,
			},
			reverseProxy:     true,
			validator:        testValidator(true),
			expectedRedirect: "https://a-service.example.com/foo/bar",
		}),
		Entry("Non-proxied request with spoofed headers, wouldn't redirect", getRedirectTableInput{
			requestURL: "https://oauth.example.com/foo?bar",
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "a-service.example.com",
				"X-Forwarded-Uri":   fooBar,
			},
			reverseProxy:     false,
			validator:        testValidator(true),
			expectedRedirect: "/foo?bar",
		}),
		Entry("Proxied request with headers, under ProxyPrefix, redirects to  root", getRedirectTableInput{
			requestURL: "https://oauth.example.com" + testProxyPrefix + fooBar,
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "a-service.example.com",
				"X-Forwarded-Uri":   testProxyPrefix + fooBar,
			},
			reverseProxy:     true,
			validator:        testValidator(true),
			expectedRedirect: "https://a-service.example.com/",
		}),
		Entry("Proxied request with port, under ProxyPrefix, redirects to  root", getRedirectTableInput{
			requestURL: "https://oauth.example.com" + testProxyPrefix + fooBar,
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "a-service.example.com:8443",
				"X-Forwarded-Uri":   testProxyPrefix + fooBar,
			},
			reverseProxy:     true,
			validator:        testValidator(true),
			expectedRedirect: "https://a-service.example.com:8443/",
		}),
		Entry("Proxied request with headers, missing URI header, redirects to the desired redirect URL", getRedirectTableInput{
			requestURL: "https://oauth.example.com/foo?bar",
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "a-service.example.com",
			},
			reverseProxy:     true,
			validator:        testValidator(true),
			expectedRedirect: "https://a-service.example.com/foo?bar",
		}),
		Entry("Proxied request without headers, with reverse proxy enabled, redirects to the desired URL", getRedirectTableInput{
			requestURL:       "https://oauth.example.com/foo?bar",
			headers:          nil,
			reverseProxy:     true,
			validator:        testValidator(true),
			expectedRedirect: "/foo?bar",
		}),
		Entry("Proxied request with X-Auth-Request-Redirect, outside of ProxyPrefix, redirects to proxied URL", getRedirectTableInput{
			requestURL: "https://oauth.example.com/foo/bar",
			headers: map[string]string{
				"X-Auth-Request-Redirect": "https://a-service.example.com/foo/bar",
			},
			reverseProxy:     true,
			validator:        testValidator(true),
			expectedRedirect: "https://a-service.example.com/foo/bar",
		}),
		Entry("Proxied request with RD parameter, outside of ProxyPrefix, redirects to proxied URL", getRedirectTableInput{
			requestURL:       "https://oauth.example.com/foo/bar?rd=https%3A%2F%2Fa%2Dservice%2Eexample%2Ecom%2Ffoo%2Fbar",
			headers:          nil,
			reverseProxy:     false,
			validator:        testValidator(true),
			expectedRedirect: "https://a-service.example.com/foo/bar",
		}),
		Entry("Proxied request with RD parameter and all headers set, reverse proxy disabled, redirects to proxied URL based on the RD parameter", getRedirectTableInput{
			requestURL: "https://oauth.example.com/foo/bar?rd=https%3A%2F%2Fa%2Dservice%2Eexample%2Ecom%2Ffoo%2Fjazz",
			headers: map[string]string{
				"X-Auth-Request-Redirect": "https://a-service.example.com/foo/baz",
				"X-Forwarded-Proto":       "http",
				"X-Forwarded-Host":        "another-service.example.com",
				"X-Forwarded-Uri":         "/seasons/greetings",
			},
			reverseProxy:     false,
			validator:        testValidator(true),
			expectedRedirect: "https://a-service.example.com/foo/jazz",
		}),
		Entry("Proxied request with RD parameter and some headers set, reverse proxy enabled, redirects to proxied URL based on the RD parameter", getRedirectTableInput{
			requestURL: "https://oauth.example.com/foo/bar?rd=https%3A%2F%2Fa%2Dservice%2Eexample%2Ecom%2Ffoo%2Fjazz",
			headers: map[string]string{
				"X-Forwarded-Proto": "http",
				"X-Forwarded-Host":  "another-service.example.com",
				"X-Forwarded-Uri":   "/seasons/greetings",
			},
			reverseProxy:     true,
			validator:        testValidator(true),
			expectedRedirect: "https://a-service.example.com/foo/jazz",
		}),
		Entry("Proxied request with invalid RD parameter and some headers set, reverse proxy enabled, redirects to proxied URL based on the headers", getRedirectTableInput{
			requestURL: "https://oauth.example.com/foo/bar?rd=http%3A%2F%2Fanother%2Dservice%2Eexample%2Ecom%2Ffoo%2Fjazz",
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "a-service.example.com",
				"X-Forwarded-Uri":   fooBar,
			},
			reverseProxy:     true,
			validator:        testValidator(false, "https://a-service.example.com/foo/bar"),
			expectedRedirect: "https://a-service.example.com/foo/bar",
		}),
	)
})
