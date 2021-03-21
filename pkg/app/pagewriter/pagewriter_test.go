package pagewriter

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Writer", func() {
	Context("NewWriter", func() {
		var writer Writer
		var opts Opts
		var request *http.Request

		BeforeEach(func() {
			opts = Opts{
				TemplatesPath:    "",
				ProxyPrefix:      "/prefix",
				Footer:           "<Footer>",
				Version:          "<Version>",
				Debug:            false,
				DisplayLoginForm: false,
				ProviderName:     "<ProviderName>",
				SignInMessage:    "<SignInMessage>",
			}

			request = httptest.NewRequest("", "http://127.0.0.1/", nil)
		})

		Context("With no custom templates", func() {
			BeforeEach(func() {
				var err error
				writer, err = NewWriter(opts)
				Expect(err).ToNot(HaveOccurred())
			})

			It("Writes the default error template", func() {
				recorder := httptest.NewRecorder()
				writer.WriteErrorPage(recorder, ErrorPageOpts{
					Status:      500,
					RedirectURL: "/redirect",
					AppError:    "Some debug error",
				})

				body, err := ioutil.ReadAll(recorder.Result().Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(HavePrefix("\n<!DOCTYPE html>"))
			})

			It("Writes the default sign in template", func() {
				recorder := httptest.NewRecorder()
				writer.WriteSignInPage(recorder, request, "/redirect")

				body, err := ioutil.ReadAll(recorder.Result().Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(HavePrefix("\n<!DOCTYPE html>"))
			})
		})

		Context("With custom templates", func() {
			var customDir string

			BeforeEach(func() {
				var err error
				customDir, err = ioutil.TempDir("", "oauth2-proxy-pagewriter-test")
				Expect(err).ToNot(HaveOccurred())

				templateHTML := `Custom Template`
				signInFile := filepath.Join(customDir, signInTemplateName)
				Expect(ioutil.WriteFile(signInFile, []byte(templateHTML), 0600)).To(Succeed())
				errorFile := filepath.Join(customDir, errorTemplateName)
				Expect(ioutil.WriteFile(errorFile, []byte(templateHTML), 0600)).To(Succeed())

				opts.TemplatesPath = customDir

				writer, err = NewWriter(opts)
				Expect(err).ToNot(HaveOccurred())
			})

			AfterEach(func() {
				Expect(os.RemoveAll(customDir)).To(Succeed())
			})

			It("Writes the custom error template", func() {
				recorder := httptest.NewRecorder()
				writer.WriteErrorPage(recorder, ErrorPageOpts{
					Status:      500,
					RedirectURL: "/redirect",
					AppError:    "Some debug error",
				})

				body, err := ioutil.ReadAll(recorder.Result().Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal("Custom Template"))
			})

			It("Writes the custom sign in template", func() {
				recorder := httptest.NewRecorder()
				writer.WriteSignInPage(recorder, request, "/redirect")

				body, err := ioutil.ReadAll(recorder.Result().Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal("Custom Template"))
			})
		})

		Context("With an invalid custom template", func() {
			var customDir string

			BeforeEach(func() {
				var err error
				customDir, err = ioutil.TempDir("", "oauth2-proxy-pagewriter-test")
				Expect(err).ToNot(HaveOccurred())

				templateHTML := `{{ Custom Broken Template`
				signInFile := filepath.Join(customDir, signInTemplateName)
				Expect(ioutil.WriteFile(signInFile, []byte(templateHTML), 0600)).To(Succeed())

				opts.TemplatesPath = customDir
			})

			AfterEach(func() {
				Expect(os.RemoveAll(customDir)).To(Succeed())
			})

			It("Should return an error", func() {
				writer, err := NewWriter(opts)
				Expect(err).To(MatchError(ContainSubstring("template: sign_in.html:1: function \"Custom\" not defined")))
				Expect(writer).To(BeNil())
			})
		})
	})
})
