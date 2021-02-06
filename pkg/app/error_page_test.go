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
			Expect(string(body)).To(Equal("Forbidden Access Denied /prefix/ 403 /redirect Custom Footer Text v0.0.0-test"))
		})
	})

	Context("ProxyErrorHandler", func() {
		It("Writes a bad gateway error the response writer", func() {
			req := httptest.NewRequest("", "/bad-gateway", nil)
			recorder := httptest.NewRecorder()
			errorPage.ProxyErrorHandler(recorder, req, errors.New("some upstream error"))

			body, err := ioutil.ReadAll(recorder.Result().Body)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(body)).To(Equal("Bad Gateway Error proxying to upstream server /prefix/ 502  Custom Footer Text v0.0.0-test"))
		})
	})
})
