package pagewriter

import (
	"errors"
	"html/template"
	"io"
	"net/http/httptest"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Error Page Writer", func() {
	var errorPage *errorPageWriter

	BeforeEach(func() {
		tmpl, err := template.New("").Parse("{{.Title}} {{.Message}} {{.ProxyPrefix}} {{.StatusCode}} {{.Redirect}} {{.RequestID}} {{.Footer}} {{.Version}}")
		Expect(err).ToNot(HaveOccurred())

		errorPage = &errorPageWriter{
			template:    tmpl,
			proxyPrefix: "/prefix/",
			footer:      "Custom Footer Text",
			version:     "v0.0.0-test",
		}
	})

	Context("WriteErrorPage", func() {
		It("Writes the template to the response writer", func() {
			recorder := httptest.NewRecorder()
			errorPage.WriteErrorPage(recorder, ErrorPageOpts{
				Status:      403,
				RedirectURL: "/redirect",
				RequestID:   testRequestID,
				AppError:    "Access Denied",
			})

			body, err := io.ReadAll(recorder.Result().Body)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(body)).To(Equal("Forbidden You do not have permission to access this resource. /prefix/ 403 /redirect 11111111-2222-4333-8444-555555555555 Custom Footer Text v0.0.0-test"))
		})

		It("With a different code, uses the stock message for the correct code", func() {
			recorder := httptest.NewRecorder()
			errorPage.WriteErrorPage(recorder, ErrorPageOpts{
				Status:      500,
				RedirectURL: "/redirect",
				RequestID:   testRequestID,
				AppError:    "Access Denied",
			})

			body, err := io.ReadAll(recorder.Result().Body)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(body)).To(Equal("Internal Server Error Oops! Something went wrong. For more information contact your server administrator. /prefix/ 500 /redirect 11111111-2222-4333-8444-555555555555 Custom Footer Text v0.0.0-test"))
		})

		It("With a message override, uses the message", func() {
			recorder := httptest.NewRecorder()
			errorPage.WriteErrorPage(recorder, ErrorPageOpts{
				Status:      403,
				RedirectURL: "/redirect",
				RequestID:   testRequestID,
				AppError:    "Access Denied",
				Messages: []interface{}{
					"An extra message: %s",
					"with more context.",
				},
			})

			body, err := io.ReadAll(recorder.Result().Body)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(body)).To(Equal("Forbidden An extra message: with more context. /prefix/ 403 /redirect 11111111-2222-4333-8444-555555555555 Custom Footer Text v0.0.0-test"))
		})

		It("Sanitizes malicious user input", func() {
			recorder := httptest.NewRecorder()
			errorPage.WriteErrorPage(recorder, ErrorPageOpts{
				Status:      403,
				RedirectURL: "/redirect",
				RequestID:   "<script>alert(1)</script>",
				AppError:    "Access Denied",
			})

			body, err := io.ReadAll(recorder.Result().Body)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(body)).To(Equal("Forbidden You do not have permission to access this resource. /prefix/ 403 /redirect &lt;script&gt;alert(1)&lt;/script&gt; Custom Footer Text v0.0.0-test"))
		})
	})

	Context("ProxyErrorHandler", func() {
		It("Writes a bad gateway error the response writer", func() {
			req := httptest.NewRequest("", "/bad-gateway", nil)
			req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{
				RequestID: testRequestID,
			})
			recorder := httptest.NewRecorder()
			errorPage.ProxyErrorHandler(recorder, req, errors.New("some upstream error"))

			body, err := io.ReadAll(recorder.Result().Body)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(body)).To(Equal("Bad Gateway There was a problem connecting to the upstream server. /prefix/ 502  11111111-2222-4333-8444-555555555555 Custom Footer Text v0.0.0-test"))
		})
	})

	Context("With Debug enabled", func() {
		BeforeEach(func() {
			tmpl, err := template.New("").Parse("{{.Message}}")
			Expect(err).ToNot(HaveOccurred())

			errorPage.template = tmpl
			errorPage.debug = true
		})

		Context("WriteErrorPage", func() {
			It("Writes the detailed error in place of the message", func() {
				recorder := httptest.NewRecorder()
				errorPage.WriteErrorPage(recorder, ErrorPageOpts{
					Status:      403,
					RedirectURL: "/redirect",
					AppError:    "Debug error",
				})

				body, err := io.ReadAll(recorder.Result().Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal("Debug error"))
			})
		})

		Context("ProxyErrorHandler", func() {
			It("Writes a bad gateway error the response writer", func() {
				req := httptest.NewRequest("", "/bad-gateway", nil)
				req = middlewareapi.AddRequestScope(req, &middlewareapi.RequestScope{
					RequestID: testRequestID,
				})
				recorder := httptest.NewRecorder()
				errorPage.ProxyErrorHandler(recorder, req, errors.New("some upstream error"))

				body, err := io.ReadAll(recorder.Result().Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal("some upstream error"))
			})
		})
	})
})
