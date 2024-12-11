package pagewriter

import (
	"bytes"
	"html/template"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Templates", func() {
	var customDir string

	BeforeEach(func() {
		var err error
		customDir, err = os.MkdirTemp("", "oauth2-proxy-templates-test")
		Expect(err).ToNot(HaveOccurred())

		templateHTML := `{{.TestString}} {{.TestString | ToLower}} {{.TestString | ToUpper}}`
		signInFile := filepath.Join(customDir, signInTemplateName)
		Expect(os.WriteFile(signInFile, []byte(templateHTML), 0600)).To(Succeed())
		errorFile := filepath.Join(customDir, errorTemplateName)
		Expect(os.WriteFile(errorFile, []byte(templateHTML), 0600)).To(Succeed())
	})

	AfterEach(func() {
		Expect(os.RemoveAll(customDir)).To(Succeed())
	})

	Context("loadTemplates", func() {
		var data interface{}
		var t *template.Template

		BeforeEach(func() {
			data = struct {
				// For default templates
				ProxyPrefix string
				Redirect    string
				Footer      string

				// For default sign_in template
				SignInMessage string
				ProviderName  string
				CustomLogin   bool
				LogoData      string

				// For default error template
				StatusCode int
				Title      string
				Message    string
				RequestID  string

				// For custom templates
				TestString string
			}{
				ProxyPrefix: "<proxy-prefix>",
				Redirect:    "<redirect>",
				Footer:      "<footer>",

				SignInMessage: "<sign-in-message>",
				ProviderName:  "<provider-name>",
				CustomLogin:   false,
				LogoData:      "<logo>",

				StatusCode: 404,
				Title:      "<title>",
				Message:    "<message>",
				RequestID:  "<request-id>",

				TestString: "Testing",
			}
		})

		Context("With no custom directory", func() {
			BeforeEach(func() {
				var err error
				t, err = loadTemplates("")
				Expect(err).ToNot(HaveOccurred())
			})

			It("Use the default sign_in page", func() {
				buf := bytes.NewBuffer([]byte{})
				Expect(t.ExecuteTemplate(buf, signInTemplateName, data)).To(Succeed())
				Expect(buf.String()).To(HavePrefix("\n<!DOCTYPE html>"))
			})

			It("Use the default error page", func() {
				buf := bytes.NewBuffer([]byte{})
				Expect(t.ExecuteTemplate(buf, errorTemplateName, data)).To(Succeed())
				Expect(buf.String()).To(HavePrefix("\n<!DOCTYPE html>"))
			})
		})

		Context("With a custom directory", func() {
			Context("With both templates", func() {
				BeforeEach(func() {
					var err error
					t, err = loadTemplates(customDir)
					Expect(err).ToNot(HaveOccurred())
				})

				It("Use the custom sign_in page", func() {
					buf := bytes.NewBuffer([]byte{})
					Expect(t.ExecuteTemplate(buf, signInTemplateName, data)).To(Succeed())
					Expect(buf.String()).To(Equal("Testing testing TESTING"))
				})

				It("Use the custom error page", func() {
					buf := bytes.NewBuffer([]byte{})
					Expect(t.ExecuteTemplate(buf, errorTemplateName, data)).To(Succeed())
					Expect(buf.String()).To(Equal("Testing testing TESTING"))
				})
			})

			Context("With no error template", func() {
				BeforeEach(func() {
					Expect(os.Remove(filepath.Join(customDir, errorTemplateName))).To(Succeed())

					var err error
					t, err = loadTemplates(customDir)
					Expect(err).ToNot(HaveOccurred())
				})

				It("Use the custom sign_in page", func() {
					buf := bytes.NewBuffer([]byte{})
					Expect(t.ExecuteTemplate(buf, signInTemplateName, data)).To(Succeed())
					Expect(buf.String()).To(Equal("Testing testing TESTING"))
				})

				It("Use the default error page", func() {
					buf := bytes.NewBuffer([]byte{})
					Expect(t.ExecuteTemplate(buf, errorTemplateName, data)).To(Succeed())
					Expect(buf.String()).To(HavePrefix("\n<!DOCTYPE html>"))
				})
			})

			Context("With no sign_in template", func() {
				BeforeEach(func() {
					Expect(os.Remove(filepath.Join(customDir, signInTemplateName))).To(Succeed())

					var err error
					t, err = loadTemplates(customDir)
					Expect(err).ToNot(HaveOccurred())
				})

				It("Use the default sign_in page", func() {
					buf := bytes.NewBuffer([]byte{})
					Expect(t.ExecuteTemplate(buf, signInTemplateName, data)).To(Succeed())
					Expect(buf.String()).To(HavePrefix("\n<!DOCTYPE html>"))
				})

				It("Use the custom error page", func() {
					buf := bytes.NewBuffer([]byte{})
					Expect(t.ExecuteTemplate(buf, errorTemplateName, data)).To(Succeed())
					Expect(buf.String()).To(Equal("Testing testing TESTING"))
				})
			})

			Context("With an invalid sign_in template", func() {
				BeforeEach(func() {
					signInFile := filepath.Join(customDir, signInTemplateName)
					Expect(os.WriteFile(signInFile, []byte("{{"), 0600))
				})

				It("Should return an error when loading templates", func() {
					t, err := loadTemplates(customDir)
					Expect(err).To(MatchError(HavePrefix("could not add Sign In template:")))
					Expect(t).To(BeNil())
				})
			})

			Context("With an invalid error template", func() {
				BeforeEach(func() {
					errorFile := filepath.Join(customDir, errorTemplateName)
					Expect(os.WriteFile(errorFile, []byte("{{"), 0600))
				})

				It("Should return an error when loading templates", func() {
					t, err := loadTemplates(customDir)
					Expect(err).To(MatchError(HavePrefix("could not add Error template:")))
					Expect(t).To(BeNil())
				})
			})
		})
	})

	Context("isFile", func() {
		It("with a valid file", func() {
			Expect(isFile(filepath.Join(customDir, signInTemplateName))).To(BeTrue())
		})

		It("with a directory", func() {
			Expect(isFile(customDir)).To(BeFalse())
		})

		It("with an invalid file", func() {
			Expect(isFile(filepath.Join(customDir, "does_not_exist.html"))).To(BeFalse())
		})
	})
})
