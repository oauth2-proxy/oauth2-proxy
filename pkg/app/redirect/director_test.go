package redirect

import (
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

var _ = Describe("forward_auth redirect preservation (issue #2940)", func() {
	// These tests model the Caddy `forward_auth` (and nginx `auth_request`)
	// flow: when /oauth2/auth returns 401, the reverse proxy redirects the
	// client to /oauth2/sign_in?rd={scheme}://{host}{uri}. The {uri} includes
	// the originally requested path and query, so `rd` is an absolute URL for
	// the same host the client used to reach the proxy.
	//
	// The Caddy integration docs require --reverse-proxy=true but do not mention
	// --whitelist-domain. Without it the absolute `rd` used to be rejected and,
	// because sign_in/start are served under the proxy prefix, the redirect
	// collapsed to "/", silently losing the originally requested URL (and its
	// query) after login.
	var (
		appDirector    AppDirector
		trustedProxies *ip.NetSet
	)

	BeforeEach(func() {
		var err error
		trustedProxies, err = ip.ParseNetSet([]string{"127.0.0.1"})
		Expect(err).ToNot(HaveOccurred())
		appDirector = NewAppDirector(AppDirectorOpts{
			ProxyPrefix: testProxyPrefix,
			// No --whitelist-domain configured, matching the Caddy docs.
			Validator: NewValidator([]string{}),
		})
	})

	// makeSignInRequest builds the /oauth2/sign_in request that Caddy's
	// `redir * /oauth2/sign_in?rd={scheme}://{host}{uri}` produces for an
	// original request on the given host, with `rd` set to rd.
	makeSignInRequest := func(host, rd string) *http.Request {
		req, _ := http.NewRequest("GET", "https://oauth2-proxy.internal/oauth2/sign_in?rd="+rd, nil)
		req.Header.Set("X-Forwarded-Proto", "http")
		req.Header.Set("X-Forwarded-Host", host)
		// Caddy's `reverse_proxy /oauth2/* { header_up X-Forwarded-Uri {uri} }`
		// sets X-Forwarded-Uri to the sign_in request's own URI, which is under
		// the proxy prefix.
		req.Header.Set("X-Forwarded-Uri", "/oauth2/sign_in?rd="+rd)
		req.RemoteAddr = "127.0.0.1:4180"
		req = middleware.AddRequestScope(req, &middleware.RequestScope{
			ReverseProxy:   true,
			TrustedProxies: trustedProxies,
		})
		return req
	}

	It("preserves the originally requested path and query from a same-host absolute rd", func() {
		// Original request was /echo/foo?bar=baz on localhost.
		req := makeSignInRequest("localhost", "http://localhost/echo/foo?bar=baz")
		redirect, err := appDirector.GetRedirect(req)
		Expect(err).ToNot(HaveOccurred())
		Expect(redirect).To(Equal("/echo/foo?bar=baz"))
	})

	It("preserves the path when the same-host rd includes a port", func() {
		req := makeSignInRequest("localhost:8080", "http://localhost:8080/echo/foo?bar=baz")
		redirect, err := appDirector.GetRedirect(req)
		Expect(err).ToNot(HaveOccurred())
		Expect(redirect).To(Equal("/echo/foo?bar=baz"))
	})

	It("preserves the absolute rd as-is when the host is whitelisted", func() {
		whitelisted := NewAppDirector(AppDirectorOpts{
			ProxyPrefix: testProxyPrefix,
			Validator:   NewValidator([]string{"localhost"}),
		})
		req := makeSignInRequest("localhost", "http://localhost/echo/foo?bar=baz")
		redirect, err := whitelisted.GetRedirect(req)
		Expect(err).ToNot(HaveOccurred())
		Expect(redirect).To(Equal("http://localhost/echo/foo?bar=baz"))
	})

	It("does not redirect to a different, non-whitelisted host's path", func() {
		// rd points at evil.example.com while the request was served on
		// localhost: the path must not be extracted and the redirect must not
		// leak the attacker-controlled host.
		req := makeSignInRequest("localhost", "http://evil.example.com/echo/foo")
		redirect, err := appDirector.GetRedirect(req)
		Expect(err).ToNot(HaveOccurred())
		Expect(redirect).To(Equal("/"))
	})

	It("still rejects open-redirect rd values", func() {
		// Extracted paths are re-validated, so protocol-relative and other
		// open-redirect payloads are rejected even when the host matches.
		req := makeSignInRequest("localhost", "//evil.example.com/path")
		redirect, err := appDirector.GetRedirect(req)
		Expect(err).ToNot(HaveOccurred())
		Expect(redirect).To(Equal("/"))
	})
})
