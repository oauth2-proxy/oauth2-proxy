package app

import (
	"html/template"
	"io/ioutil"
	"net/http/httptest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Error Page", func() {

	Context("Render", func() {
		It("Writes the template to the response writer", func() {
			tmpl, err := template.New("").Parse("{{.Title}} {{.Message}} {{.ProxyPrefix}} {{.StatusCode}} {{.Redirect}} {{.Footer}} {{.Version}}")
			Expect(err).ToNot(HaveOccurred())

			errorPage := &ErrorPage{
				Template:    tmpl,
				ProxyPrefix: "/prefix/",
				Footer:      "Custom Footer Text",
				Version:     "v0.0.0-test",
			}

			recorder := httptest.NewRecorder()
			errorPage.Render(recorder, 403, "/redirect", "Access Denied")

			body, err := ioutil.ReadAll(recorder.Result().Body)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(body)).To(Equal("Forbidden Access Denied /prefix/ 403 /redirect Custom Footer Text v0.0.0-test"))
		})
	})

})
