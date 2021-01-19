package middleware

import (
	"net/http"
	"net/http/httptest"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
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
	})
})
