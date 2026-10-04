package redirect

import (
	"crypto/tls"
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/ip"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const testProxyPrefix = "/oauth2"

var _ = Describe("Director Suite", func() {
	type getRedirectTableInput struct {
		requestURL       string
		directTLS        bool
		headers          map[string]string
		reverseProxy     bool
		validator        Validator
		includeHost      bool
		scheme           string
		expectedRedirect string
	}

	const fooBar = "/foo/bar"
	DescribeTable("GetRedirect",
		func(in getRedirectTableInput) {
			appDirector := NewAppDirector(AppDirectorOpts{
				ProxyPrefix: testProxyPrefix,
				Validator:   in.validator,
				IncludeHost: in.includeHost,
				Scheme:      in.scheme,
			})

			req, _ := http.NewRequest("GET", in.requestURL, nil)
			if in.directTLS {
				req.TLS = &tls.ConnectionState{}
			}
			for header, value := range in.headers {
				if value != "" {
					req.Header.Add(header, value)
				}
			}
			scope := &middleware.RequestScope{
				ReverseProxy: in.reverseProxy,
			}
			if in.reverseProxy {
				req.RemoteAddr = "127.0.0.1:4180"
				trustedProxies, err := ip.ParseNetSet([]string{"127.0.0.1"})
				Expect(err).ToNot(HaveOccurred())
				scope.TrustedProxies = trustedProxies
			}
			req = middleware.AddRequestScope(req, scope)

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
		Entry("Request to a whitelisted host, redirects to the full request URL", getRedirectTableInput{
			requestURL:       "https://oauth.example.com/foo?bar",
			headers:          nil,
			reverseProxy:     false,
			validator:        NewValidator([]string{"oauth.example.com"}),
			includeHost:      true,
			expectedRedirect: "https://oauth.example.com/foo?bar",
		}),
		Entry("Request to a non-whitelisted host, redirects to root", getRedirectTableInput{
			requestURL:       "https://oauth.example.com/foo?bar",
			headers:          nil,
			reverseProxy:     false,
			validator:        NewValidator([]string{"other.example.com"}),
			includeHost:      true,
			expectedRedirect: "/",
		}),
		Entry("Request to a whitelisted host with a configured HTTPS scheme, redirects to the HTTPS URL", getRedirectTableInput{
			requestURL:       "//app.example.com/foo?bar",
			headers:          nil,
			reverseProxy:     false,
			validator:        NewValidator([]string{"app.example.com"}),
			includeHost:      true,
			scheme:           "https",
			expectedRedirect: "https://app.example.com/foo?bar",
		}),
		Entry("Request to a whitelisted host without a configured scheme, redirects to the HTTP URL", getRedirectTableInput{
			requestURL:       "//app.example.com/foo?bar",
			headers:          nil,
			reverseProxy:     false,
			validator:        NewValidator([]string{"app.example.com"}),
			includeHost:      true,
			expectedRedirect: "http://app.example.com/foo?bar",
		}),
		Entry("Request to a whitelisted host over a direct TLS connection, redirects to the HTTPS URL", getRedirectTableInput{
			requestURL:       "//app.example.com/foo?bar",
			directTLS:        true,
			headers:          nil,
			reverseProxy:     false,
			validator:        NewValidator([]string{"app.example.com"}),
			includeHost:      true,
			expectedRedirect: "https://app.example.com/foo?bar",
		}),
		Entry("Request under the proxy prefix on a whitelisted host, redirects to the request host root", getRedirectTableInput{
			requestURL:       "https://app.example.com" + testProxyPrefix + fooBar,
			headers:          nil,
			reverseProxy:     false,
			validator:        NewValidator([]string{"app.example.com"}),
			includeHost:      true,
			expectedRedirect: "https://app.example.com/",
		}),
		Entry("Proxied request to a whitelisted host without headers, redirects to the full request URL", getRedirectTableInput{
			requestURL:       "https://oauth.example.com/foo?bar",
			headers:          nil,
			reverseProxy:     true,
			validator:        NewValidator([]string{"oauth.example.com"}),
			includeHost:      true,
			expectedRedirect: "https://oauth.example.com/foo?bar",
		}),
		Entry("Proxied request to a whitelisted host with X-Forwarded-Proto, redirects to the full request URL", getRedirectTableInput{
			requestURL: "http://oauth.example.com/foo?bar",
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
			},
			reverseProxy:     true,
			validator:        NewValidator([]string{"oauth.example.com"}),
			includeHost:      true,
			expectedRedirect: "https://oauth.example.com/foo?bar",
		}),
		Entry("Proxied request with a non-whitelisted X-Forwarded-Host, redirects to root", getRedirectTableInput{
			requestURL: "https://hop.internal/foo?bar",
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "a-service.example.com",
			},
			reverseProxy:     true,
			validator:        NewValidator([]string{"hop.internal"}),
			includeHost:      true,
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
		Entry("Non-proxied request with spoofed headers to a whitelisted host, redirects to the full request URL of the actual host", getRedirectTableInput{
			requestURL: "https://oauth.example.com/foo?bar",
			headers: map[string]string{
				"X-Forwarded-Proto": "https",
				"X-Forwarded-Host":  "a-service.example.com",
				"X-Forwarded-Uri":   fooBar,
			},
			reverseProxy:     false,
			validator:        testValidator(true),
			includeHost:      true,
			expectedRedirect: "https://oauth.example.com/foo?bar",
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

	It("ignores forwarded headers from an untrusted remote address", func() {
		appDirector := NewAppDirector(AppDirectorOpts{
			ProxyPrefix: testProxyPrefix,
			Validator:   testValidator(true),
		})

		req, _ := http.NewRequest("GET", "https://oauth.example.com/foo?bar", nil)
		req.RemoteAddr = "192.0.2.10:4180"
		req.Header.Add("X-Forwarded-Proto", "https")
		req.Header.Add("X-Forwarded-Host", "a-service.example.com")
		req.Header.Add("X-Forwarded-Uri", fooBar)
		trustedProxies, err := ip.ParseNetSet([]string{"127.0.0.1"})
		Expect(err).ToNot(HaveOccurred())
		req = middleware.AddRequestScope(req, &middleware.RequestScope{
			ReverseProxy:   true,
			TrustedProxies: trustedProxies,
		})

		redirect, err := appDirector.GetRedirect(req)
		Expect(err).ToNot(HaveOccurred())
		Expect(redirect).To(Equal("/foo?bar"))
	})
})
