package app

import (
	"html/template"
	"io/ioutil"
	"net/http/httptest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("SignIn Page Writer", func() {
	var signInPage *signInPageWriter

	BeforeEach(func() {
		errorTmpl, err := template.New("").Parse("{{.Title}}")
		Expect(err).ToNot(HaveOccurred())
		errorPage := &errorPageWriter{
			template: errorTmpl,
		}

		tmpl, err := template.New("").Parse("{{.ProxyPrefix}} {{.ProviderName}} {{.SignInMessage}} {{.Footer}} {{.Version}} {{.Redirect}} {{.CustomLogin}}")
		Expect(err).ToNot(HaveOccurred())

		signInPage = &signInPageWriter{
			template:         tmpl,
			errorPageWriter:  errorPage,
			proxyPrefix:      "/prefix/",
			providerName:     "My Provider",
			signInMessage:    "Sign In Here",
			footer:           "Custom Footer Text",
			version:          "v0.0.0-test",
			displayLoginForm: true,
		}
	})

	Context("WriteSignInPage", func() {
		It("Writes the template to the response writer", func() {
			recorder := httptest.NewRecorder()
			signInPage.WriteSignInPage(recorder, "/redirect")

			body, err := ioutil.ReadAll(recorder.Result().Body)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(body)).To(Equal("/prefix/ My Provider Sign In Here Custom Footer Text v0.0.0-test /redirect true"))
		})

		It("Writes an error if the template can't be rendered", func() {
			// Overwrite the template with something bad
			tmpl, err := template.New("").Parse("{{.Unknown}}")
			Expect(err).ToNot(HaveOccurred())
			signInPage.template = tmpl

			recorder := httptest.NewRecorder()
			signInPage.WriteSignInPage(recorder, "/redirect")

			body, err := ioutil.ReadAll(recorder.Result().Body)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(body)).To(Equal("Internal Server Error"))
		})
	})
})
