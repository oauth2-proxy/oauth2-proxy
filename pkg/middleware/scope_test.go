package middleware

import (
	"net/http"
	"net/http/httptest"

	"github.com/google/uuid"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	requestutil "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests/util"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const (
	testRequestID = "11111111-2222-4333-8444-555555555555"
	// mockRand io.Reader below counts bytes from 0-255 in order
	testRandomUUID = "00010203-0405-4607-8809-0a0b0c0d0e0f"
)

var _ = Describe("Scope Suite", func() {
	Context("NewScope", func() {
		var request, nextRequest *http.Request
		var rw http.ResponseWriter

		BeforeEach(func() {
			var err error
			request, err = http.NewRequest("", "http://127.0.0.1/", nil)
			Expect(err).ToNot(HaveOccurred())

			rw = httptest.NewRecorder()
		})

		Context("ReverseProxy is false", func() {
			BeforeEach(func() {
				handler := NewScope(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					nextRequest = r
					w.WriteHeader(200)
				}))
				handler.ServeHTTP(rw, request)
			})

			It("does not add a scope to the original request", func() {
				Expect(request.Context().Value(middlewareapi.RequestScopeKey)).To(BeNil())
			})

			It("cannot load a scope from the original request using GetRequestScope", func() {
				Expect(middlewareapi.GetRequestScope(request)).To(BeNil())
			})

			It("adds a scope to the request for the next handler", func() {
				Expect(nextRequest.Context().Value(middlewareapi.RequestScopeKey)).ToNot(BeNil())
			})

			It("can load a scope from the next handler's request using GetRequestScope", func() {
				scope := middlewareapi.GetRequestScope(nextRequest)
				Expect(scope).ToNot(BeNil())
				Expect(scope.ReverseProxy).To(BeFalse())
			})
		})

		Context("ReverseProxy is true", func() {
			BeforeEach(func() {
				handler := NewScope(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					nextRequest = r
					w.WriteHeader(200)
				}))
				handler.ServeHTTP(rw, request)
			})

			It("return a scope where the ReverseProxy field is true", func() {
				scope := middlewareapi.GetRequestScope(nextRequest)
				Expect(scope).ToNot(BeNil())
				Expect(scope.ReverseProxy).To(BeTrue())
			})
		})

		Context("Request ID header is present", func() {
			BeforeEach(func() {
				request.Header.Add(requestutil.XRequestID, testRequestID)
				handler := NewScope(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					nextRequest = r
					w.WriteHeader(200)
				}))
				handler.ServeHTTP(rw, request)
			})

			It("sets the RequestID using the request", func() {
				scope := middlewareapi.GetRequestScope(nextRequest)
				Expect(scope.RequestID).To(Equal(testRequestID))
			})
		})

		Context("Request ID header is overidden", func() {
			const (
				overrideHeader    = "X-Trace-Id"
				overrideRequestID = "66666666-7777-4888-8999-aaaaaaaaaaaa"
			)

			BeforeEach(func() {
				requestutil.SetRequestIDHeader(overrideHeader)
				request.Header.Add(overrideHeader, overrideRequestID)
				handler := NewScope(false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					nextRequest = r
					w.WriteHeader(200)
				}))
				handler.ServeHTTP(rw, request)
			})

			AfterEach(func() {
				requestutil.SetRequestIDHeader("")
			})

			It("sets the RequestID using the request with a custom header", func() {
				scope := middlewareapi.GetRequestScope(nextRequest)
				Expect(scope.RequestID).To(Equal(overrideRequestID))
			})
		})

		Context("Request ID header is missing", func() {
			BeforeEach(func() {
				uuid.SetRand(mockRand{})

				handler := NewScope(true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					nextRequest = r
					w.WriteHeader(200)
				}))
				handler.ServeHTTP(rw, request)
			})

			AfterEach(func() {
				uuid.SetRand(nil)
			})

			It("sets the RequestID using a random UUID", func() {
				scope := middlewareapi.GetRequestScope(nextRequest)
				Expect(scope.RequestID).To(Equal(testRandomUUID))
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
