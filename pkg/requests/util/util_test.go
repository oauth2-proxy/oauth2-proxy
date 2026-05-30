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
		Context("trusted forwarded headers are disabled", func() {
			BeforeEach(func() {
				req = middleware.AddRequestScope(req, &middleware.RequestScope{})
			})

			It("returns the URI (without query params)", func() {
				Expect(util.GetRequestPath(req)).To(Equal(uriNoQueryParams))
			})

			It("drops fragment content from a parsed request path", func() {
				// Simulate net/http ParseRequestURI preserving '#' in URL.Path.
				req.URL.Path = "/foo/secret#/bar"
				req.URL.RawPath = "/foo/secret%23/bar"
				Expect(util.GetRequestPath(req)).To(Equal("/foo/secret"))
			})

			It("drops fragment-like suffixes from encoded number signs", func() {
				req = httptest.NewRequest(
					http.MethodGet,
					fmt.Sprintf("%s://%s/foo/secret%%23/bar?query=param", proto, host),
					nil,
				)
				req = middleware.AddRequestScope(req, &middleware.RequestScope{})
				Expect(util.GetRequestPath(req)).To(Equal("/foo/secret"))
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

			It("drops fragment-like suffixes from the X-Forwarded-Uri", func() {
				req.Header.Add("X-Forwarded-Uri", "/foo/secret%23/bar?query=param")
				Expect(util.GetRequestPath(req)).To(Equal("/foo/secret"))
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
