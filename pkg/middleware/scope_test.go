package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/pkg/apis/middleware"
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

			handler := NewScope()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextRequest = r
				w.WriteHeader(200)
			}))
			handler.ServeHTTP(rw, request)
		})

		It("does not add a scope to the original request", func() {
			Expect(request.Context().Value(requestScopeKey)).To(BeNil())
		})

		It("cannot load a scope from the original request using GetRequestScope", func() {
			Expect(GetRequestScope(request)).To(BeNil())
		})

		It("adds a scope to the request for the next handler", func() {
			Expect(nextRequest.Context().Value(requestScopeKey)).ToNot(BeNil())
		})

		It("can load a scope from the next handler's request using GetRequestScope", func() {
			Expect(GetRequestScope(nextRequest)).ToNot(BeNil())
		})
	})

	Context("GetRequestScope", func() {
		var request *http.Request

		BeforeEach(func() {
			var err error
			request, err = http.NewRequest("", "http://127.0.0.1/", nil)
			Expect(err).ToNot(HaveOccurred())
		})

		Context("with a scope", func() {
			var scope *middlewareapi.RequestScope

			BeforeEach(func() {
				scope = &middlewareapi.RequestScope{}
				contextWithScope := context.WithValue(request.Context(), requestScopeKey, scope)
				request = request.WithContext(contextWithScope)
			})

			It("returns the scope", func() {
				s := GetRequestScope(request)
				Expect(s).ToNot(BeNil())
				Expect(s).To(Equal(scope))
			})

			Context("if the scope is then modified", func() {
				BeforeEach(func() {
					Expect(scope.SaveSession).To(BeFalse())
					scope.SaveSession = true
				})

				It("returns the updated session", func() {
					s := GetRequestScope(request)
					Expect(s).ToNot(BeNil())
					Expect(s).To(Equal(scope))
					Expect(s.SaveSession).To(BeTrue())
				})
			})
		})

		Context("without a scope", func() {
			It("returns nil", func() {
				Expect(GetRequestScope(request)).To(BeNil())
			})
		})
	})
})
