package util_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/google/uuid"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests/util"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Util Suite", func() {
	const (
		proto      = "http"
		host       = "www.oauth2proxy.test"
		uri        = "/test/endpoint"
		scopeUUID  = "11111111-2222-4333-8444-555555555555"
		headerUUID = "66666666-7777-4888-8999-aaaaaaaaaaaa"
		// mockRand io.Reader below counts bytes from 0-255 in order
		randomUUID = "00010203-0405-4607-8809-0a0b0c0d0e0f"
	)
	var req *http.Request

	BeforeEach(func() {
		req = httptest.NewRequest(
			http.MethodGet,
			fmt.Sprintf("%s://%s%s", proto, host, uri),
			nil,
		)
	})

	Context("GetRequestHost", func() {
		Context("IsProxied is false", func() {
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

		Context("IsProxied is true", func() {
			BeforeEach(func() {
				req = middleware.AddRequestScope(req, &middleware.RequestScope{
					ReverseProxy: true,
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
		Context("IsProxied is false", func() {
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

		Context("IsProxied is true", func() {
			BeforeEach(func() {
				req = middleware.AddRequestScope(req, &middleware.RequestScope{
					ReverseProxy: true,
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
		Context("IsProxied is false", func() {
			BeforeEach(func() {
				req = middleware.AddRequestScope(req, &middleware.RequestScope{})
			})

			It("returns the URI", func() {
				Expect(util.GetRequestURI(req)).To(Equal(uri))
			})

			It("ignores X-Forwarded-Uri and returns the URI", func() {
				req.Header.Add("X-Forwarded-Uri", "/some/other/path")
				Expect(util.GetRequestURI(req)).To(Equal(uri))
			})
		})

		Context("IsProxied is true", func() {
			BeforeEach(func() {
				req = middleware.AddRequestScope(req, &middleware.RequestScope{
					ReverseProxy: true,
				})
			})

			It("returns the URI if X-Forwarded-Uri is not present", func() {
				Expect(util.GetRequestURI(req)).To(Equal(uri))
			})

			It("returns the X-Forwarded-Uri when present", func() {
				req.Header.Add("X-Forwarded-Uri", "/some/other/path")
				Expect(util.GetRequestURI(req)).To(Equal("/some/other/path"))
			})
		})
	})

	Context("GetRequestID", func() {
		Context("Scope is already set", func() {
			BeforeEach(func() {
				req = middleware.AddRequestScope(req, &middleware.RequestScope{
					RequestID: scopeUUID,
				})
			})

			It("returns the ID in the scope", func() {
				Expect(util.GetRequestID(req)).To(Equal(scopeUUID))
			})

			It("ignores X-Request-Id and returns the scope ID", func() {
				req.Header.Add("X-Request-Id", headerUUID)
				Expect(util.GetRequestID(req)).To(Equal(scopeUUID))
			})
		})

		Context("Scope is not set", func() {
			BeforeEach(func() {
				uuid.SetRand(mockRand{})
			})

			AfterEach(func() {
				uuid.SetRand(nil)
			})

			It("returns the ID in the X-Request-Id header when set", func() {
				req.Header.Add("X-Request-Id", headerUUID)
				Expect(util.GetRequestID(req)).To(Equal(headerUUID))
			})

			It("returns a random UUID when the header is unset", func() {
				Expect(util.GetRequestID(req)).To(Equal(randomUUID))
			})
		})
	})
})

type mockRand struct{}

func (mockRand) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(i % 256)
	}
	return len(p), nil
}
