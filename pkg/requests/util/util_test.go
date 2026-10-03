package util_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/ip"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests/util"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Util Suite", func() {
	const (
		proto              = "http"
		host               = "www.oauth2proxy.test"
		uriWithQueryParams = "/test/endpoint?query=param"
		uriNoQueryParams   = "/test/endpoint"
	)
	var req *http.Request
	var trustedProxies *ip.NetSet

	BeforeEach(func() {
		var err error
		trustedProxies, err = ip.ParseNetSet([]string{"127.0.0.1"})
		Expect(err).ToNot(HaveOccurred())

		req = httptest.NewRequest(
			http.MethodGet,
			fmt.Sprintf("%s://%s%s", proto, host, uriWithQueryParams),
			nil,
		)
	})

	Context("GetRequestHost", func() {
		Context("trusted forwarded headers are disabled", func() {
			BeforeEach(func() {
				req = middleware.AddRequestScope(req, &middleware.RequestScope{})
			})

			It("returns the host", func() {
				Expect(util.GetRequestHost(req)).To(Equal(host))
			})

			It("ignores X-Forwarded-Host and returns the host", func() {
				req.Header.Add("X-Forwarded-Host", "external.oauth2proxy.text")
				Expect(util.GetRequestHost(req)).To(Equal(host))
			})
		})

		Context("trusted forwarded headers are enabled", func() {
			BeforeEach(func() {
				req.RemoteAddr = "127.0.0.1:4180"
				req = middleware.AddRequestScope(req, &middleware.RequestScope{
					ReverseProxy:   true,
					TrustedProxies: trustedProxies,
				})
			})

			It("returns the host if X-Forwarded-Host is not present", func() {
				Expect(util.GetRequestHost(req)).To(Equal(host))
			})

			It("returns the X-Forwarded-Host when present", func() {
				req.Header.Add("X-Forwarded-Host", "external.oauth2proxy.text")
				Expect(util.GetRequestHost(req)).To(Equal("external.oauth2proxy.text"))
			})

			It("returns the first X-Forwarded-Host when multiple hosts are present", func() {
				req.Header.Add("X-Forwarded-Host", "first.host,second.host,third.host")
				Expect(util.GetRequestHost(req)).To(Equal("first.host"))
			})

			It("returns the first X-Forwarded-Host when multiple hosts are present with extra spaces", func() {
				req.Header.Add("X-Forwarded-Host", "  first.host  ,  second.host  ,  third.host  ")
				Expect(util.GetRequestHost(req)).To(Equal("first.host"))
			})
		})
	})

	Context("GetRequestProto", func() {
		Context("trusted forwarded headers are disabled", func() {
			BeforeEach(func() {
				req = middleware.AddRequestScope(req, &middleware.RequestScope{})
			})

			It("returns the scheme", func() {
				Expect(util.GetRequestProto(req)).To(Equal(proto))
			})

			It("ignores X-Forwarded-Proto and returns the scheme", func() {
				req.Header.Add("X-Forwarded-Proto", "https")
				Expect(util.GetRequestProto(req)).To(Equal(proto))
			})
		})

		Context("trusted forwarded headers are enabled", func() {
			BeforeEach(func() {
				req.RemoteAddr = "127.0.0.1:4180"
				req = middleware.AddRequestScope(req, &middleware.RequestScope{
					ReverseProxy:   true,
					TrustedProxies: trustedProxies,
				})
			})

			It("returns the scheme if X-Forwarded-Proto is not present", func() {
				Expect(util.GetRequestProto(req)).To(Equal(proto))
			})

			It("returns the X-Forwarded-Proto when present", func() {
				req.Header.Add("X-Forwarded-Proto", "https")
				Expect(util.GetRequestProto(req)).To(Equal("https"))
			})
		})
	})

	Context("GetRequestURI", func() {
		Context("trusted forwarded headers are disabled", func() {
			BeforeEach(func() {
				req = middleware.AddRequestScope(req, &middleware.RequestScope{})
			})

			It("returns the URI (with query params)", func() {
				Expect(util.GetRequestURI(req)).To(Equal(uriWithQueryParams))
			})

			It("ignores X-Forwarded-Uri and returns the URI (with query params)", func() {
				req.Header.Add("X-Forwarded-Uri", "/some/other/path")
				Expect(util.GetRequestURI(req)).To(Equal(uriWithQueryParams))
			})
		})

		Context("trusted forwarded headers are enabled", func() {
			BeforeEach(func() {
				req.RemoteAddr = "127.0.0.1:4180"
				req = middleware.AddRequestScope(req, &middleware.RequestScope{
					ReverseProxy:   true,
					TrustedProxies: trustedProxies,
				})
			})

			It("returns the URI if X-Forwarded-Uri is not present (with query params)", func() {
				Expect(util.GetRequestURI(req)).To(Equal(uriWithQueryParams))
			})

			It("returns the X-Forwarded-Uri when present (with query params)", func() {
				req.Header.Add("X-Forwarded-Uri", "/some/other/path?query=param")
				Expect(util.GetRequestURI(req)).To(Equal("/some/other/path?query=param"))
			})
		})
	})

	Context("GetRequestPath", func() {
		DescribeTable("preserves unambiguous paths without changing the request",
			func(target, expected string) {
				for _, forwarded := range []bool{false, true} {
					req = httptest.NewRequest(http.MethodGet, target, nil)
					if forwarded {
						req = httptest.NewRequest(http.MethodGet, "/oauth2/auth", nil)
						req.RemoteAddr = "127.0.0.1:4180"
						req = middleware.AddRequestScope(req, &middleware.RequestScope{
							ReverseProxy: true, TrustedProxies: trustedProxies,
						})
						req.Header.Set("X-Forwarded-Uri", target)
					}
					originalURL, originalTarget := *req.URL, req.RequestURI
					requestPath, err := util.GetRequestPath(req)
					Expect(err).NotTo(HaveOccurred())
					Expect(requestPath).To(Equal(expected))
					Expect(*req.URL).To(Equal(originalURL))
					Expect(req.RequestURI).To(Equal(originalTarget))
				}
			},
			Entry("root", "/", "/"),
			Entry("public path", "/public/file", "/public/file"),
			Entry("protected path", "/protected/file", "/protected/file"),
			Entry("trailing slash", "/public/", "/public/"),
			Entry("query ignored", "/public/file?next=/../protected;v=1&tag=%23", "/public/file"),
			Entry("invalid query escape does not affect the path", "/public/file?q=%zz", "/public/file"),
			Entry("escaped space", "/public/a%20b", "/public/a b"),
			Entry("escaped letter", "/public/%66ile", "/public/file"),
			Entry("escaped Unicode", "/public/caf%C3%A9", "/public/caf\u00e9"),
			Entry("escaped slash", "/public%2ffile", "/public/file"),
			Entry("literal plus", "/public/a+b", "/public/a+b"),
			Entry("escaped plus", "/public/a%2bb", "/public/a+b"),
			Entry("escaped percent", "/public/100%25", "/public/100%"),
			Entry("dot within a segment", "/public/file.txt", "/public/file.txt"),
			Entry("multiple dots are not a parent segment", "/public/...", "/public/..."),
		)

		DescribeTable("declines ambiguous or invalid original request targets",
			func(target string) {
				req.RemoteAddr = "127.0.0.1:4180"
				req = middleware.AddRequestScope(req, &middleware.RequestScope{
					ReverseProxy: true, TrustedProxies: trustedProxies,
				})
				req.Header.Set("X-Forwarded-Uri", target)
				requestPath, err := util.GetRequestPath(req)
				Expect(err).To(HaveOccurred())
				Expect(requestPath).To(BeEmpty())
				Expect(err.Error()).NotTo(ContainSubstring("sensitive-value"))
			},
			Entry("literal parent segment", "/public/../protected?token=sensitive-value"),
			Entry("encoded parent segment", "/public/%2e%2E/protected"),
			Entry("encoded slash exposes parent segment", "/public%2f..%2fprotected"),
			Entry("current segment", "/public/./file"),
			Entry("terminal parent segment", "/public/.."),
			Entry("terminal current segment", "/public/."),
			Entry("leading double slash", "//protected/public"),
			Entry("repeated slash", "/public//file"),
			Entry("encoded repeated slash", "/public/%2ffile"),
			Entry("matrix parent segment", "/public/..;/protected"),
			Entry("encoded matrix parent segment", "/public/%2e%2e%3b/protected"),
			Entry("valid matrix parameter", "/public/file;version=1"),
			Entry("matrix parameter containing a slash", "/protected;/public"),
			Entry("invalid escape", "/public/%zz?token=sensitive-value"),
			Entry("incomplete escape", "/public/%"),
			Entry("relative target", "public/file"),
			Entry("absolute target", "https://example.com/public/file"),
			Entry("authority target", "example.com:443"),
			Entry("asterisk target", "*"),
			Entry("literal fragment", "/public#sensitive-value"),
			Entry("encoded fragment", "/public%23sensitive-value"),
			Entry("encoded question mark", "/public%3fsensitive-value"),
			Entry("backslash", "/public\\..\\protected"),
			Entry("encoded backslash", "/public%5c..%5cprotected"),
			Entry("encoded control character", "/public/%00"),
			Entry("encoded delete character", "/public/%7f"),
			Entry("unescaped space", "/public/a b"),
		)

		It("ignores a forged forwarded URI from an untrusted peer", func() {
			req.RemoteAddr = "192.0.2.10:4180"
			req = middleware.AddRequestScope(req, &middleware.RequestScope{
				ReverseProxy: true, TrustedProxies: trustedProxies,
			})
			req.Header.Set("X-Forwarded-Uri", "/public")
			Expect(util.GetRequestPath(req)).To(Equal(uriNoQueryParams))
		})

		Context("trusted forwarded headers are disabled", func() {
			BeforeEach(func() {
				req = middleware.AddRequestScope(req, &middleware.RequestScope{})
			})

			It("returns the URI (without query params)", func() {
				Expect(util.GetRequestPath(req)).To(Equal(uriNoQueryParams))
			})

			It("declines fragment content in a parsed request path", func() {
				// Simulate net/http ParseRequestURI preserving '#' in URL.Path.
				req.URL.Path = "/foo/secret#/bar"
				req.URL.RawPath = "/foo/secret%23/bar"
				requestPath, err := util.GetRequestPath(req)
				Expect(err).To(HaveOccurred())
				Expect(requestPath).To(BeEmpty())
			})

			It("declines encoded number signs", func() {
				req = httptest.NewRequest(
					http.MethodGet,
					fmt.Sprintf("%s://%s/foo/secret%%23/bar?query=param", proto, host),
					nil,
				)
				req = middleware.AddRequestScope(req, &middleware.RequestScope{})
				requestPath, err := util.GetRequestPath(req)
				Expect(err).To(HaveOccurred())
				Expect(requestPath).To(BeEmpty())
			})

			It("ignores X-Forwarded-Uri and returns the URI (without query params)", func() {
				req.Header.Add("X-Forwarded-Uri", "/some/other/path?query=param")
				Expect(util.GetRequestPath(req)).To(Equal(uriNoQueryParams))
			})
		})

		Context("trusted forwarded headers are enabled", func() {
			BeforeEach(func() {
				req.RemoteAddr = "127.0.0.1:4180"
				req = middleware.AddRequestScope(req, &middleware.RequestScope{
					ReverseProxy:   true,
					TrustedProxies: trustedProxies,
				})
			})

			It("returns the URI if X-Forwarded-Uri is not present (without query params)", func() {
				Expect(util.GetRequestPath(req)).To(Equal(uriNoQueryParams))
			})

			It("returns the X-Forwarded-Uri when present (without query params)", func() {
				req.Header.Add("X-Forwarded-Uri", "/some/other/path?query=param")
				Expect(util.GetRequestPath(req)).To(Equal("/some/other/path"))
			})

			It("declines fragment-like suffixes from the X-Forwarded-Uri", func() {
				req.Header.Add("X-Forwarded-Uri", "/foo/secret%23/bar?query=param")
				requestPath, err := util.GetRequestPath(req)
				Expect(err).To(HaveOccurred())
				Expect(requestPath).To(BeEmpty())
			})
		})
	})

	Context("CanTrustForwardedHeaders", func() {
		It("returns false when no scope is present", func() {
			Expect(util.CanTrustForwardedHeaders(req)).To(BeFalse())
		})

		It("returns true when the remote address is trusted", func() {
			req.RemoteAddr = "127.0.0.1:4180"
			req = middleware.AddRequestScope(req, &middleware.RequestScope{
				ReverseProxy:   true,
				TrustedProxies: trustedProxies,
			})

			Expect(util.CanTrustForwardedHeaders(req)).To(BeTrue())
		})

		It("returns false when the remote address is untrusted", func() {
			req.RemoteAddr = "192.0.2.10:4180"
			req = middleware.AddRequestScope(req, &middleware.RequestScope{
				ReverseProxy:   true,
				TrustedProxies: trustedProxies,
			})

			Expect(util.CanTrustForwardedHeaders(req)).To(BeFalse())
		})
	})
})
