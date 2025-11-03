package pagewriter

import (
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Static Pages", func() {
	var customDir string
	const customRobots = "User-agent: *\nAllow: /\n"
	var errorPage *errorPageWriter
	var request *http.Request

	BeforeEach(func() {
		errorTmpl, err := template.New("").Parse("{{.Title}}")
		Expect(err).ToNot(HaveOccurred())
		errorPage = &errorPageWriter{
			template: errorTmpl,
		}

		customDir, err = os.MkdirTemp("", "oauth2-proxy-static-pages-test")
		Expect(err).ToNot(HaveOccurred())

		robotsTxtFile := filepath.Join(customDir, robotsTxtName)
		Expect(os.WriteFile(robotsTxtFile, []byte(customRobots), 0400)).To(Succeed())

		request = httptest.NewRequest("", "http://127.0.0.1/", nil)
		request = middlewareapi.AddRequestScope(request, &middlewareapi.RequestScope{
			RequestID: testRequestID,
		})
	})

	AfterEach(func() {
		Expect(os.RemoveAll(customDir)).To(Succeed())
	})

	Context("Static Page Writer", func() {
		Context("With custom content", func() {
			var pageWriter *staticPageWriter

			BeforeEach(func() {
				var err error
				pageWriter, err = newStaticPageWriter(customDir, errorPage)
				Expect(err).ToNot(HaveOccurred())
			})

			Context("WriterRobotsTxt", func() {
				It("Should write the custom robots txt", func() {
					recorder := httptest.NewRecorder()
					pageWriter.WriteRobotsTxt(recorder, request)

					body, err := io.ReadAll(recorder.Result().Body)
					Expect(err).ToNot(HaveOccurred())
					Expect(string(body)).To(Equal(customRobots))

					Expect(recorder.Result().StatusCode).To(Equal(http.StatusOK))
				})
			})
		})

		Context("Without custom content", func() {
			var pageWriter *staticPageWriter

			BeforeEach(func() {
				var err error
				pageWriter, err = newStaticPageWriter("", errorPage)
				Expect(err).ToNot(HaveOccurred())
			})

			Context("WriterRobotsTxt", func() {
				It("Should write the custom robots txt", func() {
					recorder := httptest.NewRecorder()
					pageWriter.WriteRobotsTxt(recorder, request)

					body, err := io.ReadAll(recorder.Result().Body)
					Expect(err).ToNot(HaveOccurred())
					Expect(string(body)).To(Equal(string(defaultRobotsTxt)))

					Expect(recorder.Result().StatusCode).To(Equal(http.StatusOK))
				})

				It("Should serve an error if it cannot write the page", func() {
					recorder := &testBadResponseWriter{
						ResponseRecorder: httptest.NewRecorder(),
					}
					pageWriter.WriteRobotsTxt(recorder, request)

					body, err := io.ReadAll(recorder.Result().Body)
					Expect(err).ToNot(HaveOccurred())
					Expect(string(body)).To(Equal(string("Internal Server Error")))

					Expect(recorder.Result().StatusCode).To(Equal(http.StatusInternalServerError))
				})
			})
		})
	})

	Context("loadStaticPages", func() {
		Context("With custom content", func() {
			Context("And a custom robots txt", func() {
				It("Loads the custom content", func() {
					pages, err := loadStaticPages(customDir)
					Expect(err).ToNot(HaveOccurred())
					Expect(pages.pages).To(HaveLen(1))
					Expect(pages.getPage(robotsTxtName)).To(BeEquivalentTo(customRobots))
				})
			})

			Context("And no custom robots txt", func() {
				It("returns the default content", func() {
					robotsTxtFile := filepath.Join(customDir, robotsTxtName)
					Expect(os.Remove(robotsTxtFile)).To(Succeed())

					pages, err := loadStaticPages(customDir)
					Expect(err).ToNot(HaveOccurred())
					Expect(pages.pages).To(HaveLen(1))
					Expect(pages.getPage(robotsTxtName)).To(BeEquivalentTo(defaultRobotsTxt))
				})
			})
		})

		Context("Without custom content", func() {
			It("Loads the default content", func() {
				pages, err := loadStaticPages("")
				Expect(err).ToNot(HaveOccurred())
				Expect(pages.pages).To(HaveLen(1))
				Expect(pages.getPage(robotsTxtName)).To(BeEquivalentTo(defaultRobotsTxt))
			})
		})
	})
})

type testBadResponseWriter struct {
	*httptest.ResponseRecorder
	firstWriteCalled bool
}

func (b *testBadResponseWriter) Write(buf []byte) (int, error) {
	if !b.firstWriteCalled {
		b.firstWriteCalled = true
		return 0, errors.New("write closed")
	}
	return b.ResponseRecorder.Write(buf)
}
