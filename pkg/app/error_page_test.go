package app

import (
	"errors"
	"html/template"
	"io/ioutil"
	"net/http/httptest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Error Page", func() {
	var errorPage *ErrorPage

	BeforeEach(func() {
		tmpl, err := template.New("").Parse("{{.Title}} {{.Message}} {{.ProxyPrefix}} {{.StatusCode}} {{.Redirect}} {{.Footer}} {{.Version}}")
		Expect(err).ToNot(HaveOccurred())

		errorPage = &ErrorPage{
			Template:    tmpl,
			ProxyPrefix: "/prefix/",
			Footer:      "Custom Footer Text",
			Version:     "v0.0.0-test",
		}
	})

	Context("Render", func() {
		It("Writes the template to the response writer", func() {
			recorder := httptest.NewRecorder()
			errorPage.Render(recorder, 403, "/redirect", "Access Denied")

			body, err := ioutil.ReadAll(recorder.Result().Body)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(body)).To(Equal("Forbidden You do not have permission to access this resource. /prefix/ 403 /redirect Custom Footer Text v0.0.0-test"))
		})

		It("With a different code, uses the stock message for the correct code", func() {
			recorder := httptest.NewRecorder()
			errorPage.Render(recorder, 500, "/redirect", "Access Denied")

			body, err := ioutil.ReadAll(recorder.Result().Body)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(body)).To(Equal("Internal Server Error Oops! Something went wrong. For more information contact your server administrator. /prefix/ 500 /redirect Custom Footer Text v0.0.0-test"))
		})

		It("With a message override, uses the message", func() {
			recorder := httptest.NewRecorder()
			errorPage.Render(recorder, 403, "/redirect", "Access Denied", "An extra message: %s", "with more context.")

			body, err := ioutil.ReadAll(recorder.Result().Body)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(body)).To(Equal("Forbidden An extra message: with more context. /prefix/ 403 /redirect Custom Footer Text v0.0.0-test"))
		})
	})

	Context("ProxyErrorHandler", func() {
		It("Writes a bad gateway error the response writer", func() {
			req := httptest.NewRequest("", "/bad-gateway", nil)
			recorder := httptest.NewRecorder()
			errorPage.ProxyErrorHandler(recorder, req, errors.New("some upstream error"))

			body, err := ioutil.ReadAll(recorder.Result().Body)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(body)).To(Equal("Bad Gateway There was a problem connecting to the upstream server. /prefix/ 502  Custom Footer Text v0.0.0-test"))
		})
	})

	Context("With Debug enabled", func() {
		BeforeEach(func() {
			tmpl, err := template.New("").Parse("{{.Message}}")
			Expect(err).ToNot(HaveOccurred())

			errorPage.Template = tmpl
			errorPage.Debug = true
		})

		Context("Render", func() {
			It("Writes the detailed error in place of the message", func() {
				recorder := httptest.NewRecorder()
				errorPage.Render(recorder, 403, "/redirect", "Debug error")

				body, err := ioutil.ReadAll(recorder.Result().Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal("Debug error"))
			})
		})

		Context("ProxyErrorHandler", func() {
			It("Writes a bad gateway error the response writer", func() {
				req := httptest.NewRequest("", "/bad-gateway", nil)
				recorder := httptest.NewRecorder()
				errorPage.ProxyErrorHandler(recorder, req, errors.New("some upstream error"))

				body, err := ioutil.ReadAll(recorder.Result().Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal("some upstream error"))
			})
		})
	})
})
