package middleware_test

import (
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Scope Suite", func() {
	Context("GetRequestScope", func() {
		var request *http.Request

		BeforeEach(func() {
			var err error
			request, err = http.NewRequest("", "http://127.0.0.1/", nil)
			Expect(err).ToNot(HaveOccurred())
		})

		Context("with a scope", func() {
			var scope *middleware.RequestScope

			BeforeEach(func() {
				scope = &middleware.RequestScope{}
				request = middleware.AddRequestScope(request, scope)
			})

			It("returns the scope", func() {
				s := middleware.GetRequestScope(request)
				Expect(s).ToNot(BeNil())
				Expect(s).To(Equal(scope))
			})

			Context("if the scope is then modified", func() {
				BeforeEach(func() {
					Expect(scope.SaveSession).To(BeFalse())
					scope.SaveSession = true
				})

				It("returns the updated session", func() {
					s := middleware.GetRequestScope(request)
					Expect(s).ToNot(BeNil())
					Expect(s).To(Equal(scope))
					Expect(s.SaveSession).To(BeTrue())
				})
			})
		})

		Context("without a scope", func() {
			It("returns nil", func() {
				Expect(middleware.GetRequestScope(request)).To(BeNil())
			})
		})
	})
})
