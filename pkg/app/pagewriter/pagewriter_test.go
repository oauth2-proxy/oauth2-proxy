package pagewriter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	msIssuerURL = "https://login.microsoftonline.com/fabrikamb2c.onmicrosoft.com/v2.0/"
	msKeysURL   = "https://login.microsoftonline.com/fabrikamb2c.onmicrosoft.com/discovery/v2.0/keys"
)

var _ = Describe("Writer", func() {
	Context("NewWriter", func() {
		var writer Writer
		var opts Opts
		var request *http.Request
		var err error
		var pd providers.Provider

		BeforeEach(func() {
			opts = Opts{
				TemplatesPath:    "",
				ProxyPrefix:      "/prefix",
				Footer:           "<Footer>",
				Version:          "<Version>",
				Debug:            false,
				DisplayLoginForm: false,
				SignInMessage:    "<SignInMessage>",
			}

			request = httptest.NewRequest("", "http://127.0.0.1/", nil)
			providerConfig := options.Provider{
				ID:               "id",
				Type:             options.OIDCProvider,
				ClientID:         "xyz",
				ClientSecretFile: "abc",
				Scope:            "openid email profile groups",
				OIDCConfig: options.OIDCOptions{
					IssuerURL:     msIssuerURL,
					SkipDiscovery: true,
					JwksURL:       msKeysURL,
				},
			}

			pd, err = providers.NewProvider(providerConfig)
			Expect(err).ToNot(HaveOccurred())
		})

		Context("With no custom templates", func() {
			BeforeEach(func() {
				var err error
				writer, err = NewWriter(opts)
				Expect(err).ToNot(HaveOccurred())
			})

			It("Writes the default error template", func(ctx SpecContext) {
				recorder := httptest.NewRecorder()
				writer.WriteErrorPage(ctx, recorder, ErrorPageOpts{
					Status:      500,
					RedirectURL: "/redirect",
					AppError:    "Some debug error",
				})

				body, err := io.ReadAll(recorder.Result().Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(HavePrefix("\n<!DOCTYPE html>"))
			})

			It("Writes the default sign in template", func() {
				recorder := httptest.NewRecorder()

				request = request.WithContext(utils.AppendProviderToContext(request.Context(), pd))
				writer.WriteSignInPage(recorder, request, "/redirect", http.StatusOK)

				body, err := io.ReadAll(recorder.Result().Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(HavePrefix("\n<!DOCTYPE html>"))
			})
		})

		Context("With custom templates", func() {
			var customDir string

			BeforeEach(func() {
				var err error
				customDir, err = os.MkdirTemp("", "oauth2-proxy-pagewriter-test")
				Expect(err).ToNot(HaveOccurred())

				templateHTML := `Custom Template`
				signInFile := filepath.Join(customDir, signInTemplateName)
				Expect(os.WriteFile(signInFile, []byte(templateHTML), 0600)).To(Succeed())
				errorFile := filepath.Join(customDir, errorTemplateName)
				Expect(os.WriteFile(errorFile, []byte(templateHTML), 0600)).To(Succeed())

				opts.TemplatesPath = customDir

				writer, err = NewWriter(opts)
				Expect(err).ToNot(HaveOccurred())
			})

			AfterEach(func() {
				Expect(os.RemoveAll(customDir)).To(Succeed())
			})

			It("Writes the custom error template", func(ctx SpecContext) {
				recorder := httptest.NewRecorder()
				writer.WriteErrorPage(ctx, recorder, ErrorPageOpts{
					Status:      500,
					RedirectURL: "/redirect",
					AppError:    "Some debug error",
				})

				body, err := io.ReadAll(recorder.Result().Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal("Custom Template"))
			})

			It("Writes the custom sign in template", func() {
				recorder := httptest.NewRecorder()

				request = request.WithContext(utils.AppendProviderToContext(request.Context(), pd))
				writer.WriteSignInPage(recorder, request, "/redirect", http.StatusOK)
				body, err := io.ReadAll(recorder.Result().Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal("Custom Template"))
			})
		})

		Context("With an invalid custom template", func() {
			var customDir string

			BeforeEach(func() {
				var err error
				customDir, err = os.MkdirTemp("", "oauth2-proxy-pagewriter-test")
				Expect(err).ToNot(HaveOccurred())

				templateHTML := `{{ Custom Broken Template`
				signInFile := filepath.Join(customDir, signInTemplateName)
				Expect(os.WriteFile(signInFile, []byte(templateHTML), 0600)).To(Succeed())

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

	Context("WriterFuncs", func() {
		type writerFuncsTableInput struct {
			writer         Writer
			expectedStatus int
			expectedBody   string
		}
		var err error
		var pd providers.Provider

		BeforeEach(func() {

			providerConfig := options.Provider{
				ID:               "id",
				Type:             options.OIDCProvider,
				ClientID:         "xyz",
				ClientSecretFile: "abc",
				Scope:            "openid email profile groups",
				OIDCConfig: options.OIDCOptions{
					IssuerURL:     msIssuerURL,
					SkipDiscovery: true,
					JwksURL:       msKeysURL,
				},
			}

			pd, err = providers.NewProvider(providerConfig)
			if err != nil {
				Expect(err).ToNot(HaveOccurred())
			}
		})

		DescribeTable("WriteSignInPage",
			func(in writerFuncsTableInput) {
				rw := httptest.NewRecorder()
				req := httptest.NewRequest("", "/sign-in", nil)
				redirectURL := "<redirectURL>"

				req = req.WithContext(utils.AppendProviderToContext(req.Context(), pd))
				in.writer.WriteSignInPage(rw, req, redirectURL, http.StatusOK)

				Expect(rw.Result().StatusCode).To(Equal(in.expectedStatus))

				body, err := io.ReadAll(rw.Result().Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal(in.expectedBody))
			},
			Entry("With no override", writerFuncsTableInput{
				writer:         &WriterFuncs{},
				expectedStatus: 200,
				expectedBody:   "Sign In",
			}),
			Entry("With an override function", writerFuncsTableInput{
				writer: &WriterFuncs{
					SignInPageFunc: func(rw http.ResponseWriter, req *http.Request, redirectURL string, statusCode int) {
						rw.WriteHeader(202)
						rw.Write([]byte(fmt.Sprintf("%s %s", req.URL.Path, redirectURL)))
					},
				},
				expectedStatus: 202,
				expectedBody:   "/sign-in <redirectURL>",
			}),
		)

		DescribeTable("WriteErrorPage",
			func(in writerFuncsTableInput, ctx context.Context) {
				rw := httptest.NewRecorder()
				in.writer.WriteErrorPage(ctx, rw, ErrorPageOpts{
					Status:      http.StatusInternalServerError,
					RedirectURL: "<redirectURL>",
					RequestID:   "12345",
					AppError:    "application error",
				})

				Expect(rw.Result().StatusCode).To(Equal(in.expectedStatus))

				body, err := io.ReadAll(rw.Result().Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal(in.expectedBody))
			},
			Entry("With no override", writerFuncsTableInput{
				writer:         &WriterFuncs{},
				expectedStatus: 500,
				expectedBody:   "500 - application error",
			}, context.Background()),
			Entry("With an override function", writerFuncsTableInput{
				writer: &WriterFuncs{
					ErrorPageFunc: func(ctx context.Context, rw http.ResponseWriter, opts ErrorPageOpts) {
						rw.WriteHeader(503)
						rw.Write([]byte(fmt.Sprintf("%s %s", opts.RequestID, opts.RedirectURL)))
					},
				},
				expectedStatus: 503,
				expectedBody:   "12345 <redirectURL>",
			}, context.Background()),
		)

		DescribeTable("ProxyErrorHandler",
			func(in writerFuncsTableInput) {
				rw := httptest.NewRecorder()
				req := httptest.NewRequest("", "/proxy", nil)
				err := errors.New("proxy error")
				in.writer.ProxyErrorHandler(rw, req, err)

				Expect(rw.Result().StatusCode).To(Equal(in.expectedStatus))

				body, err := io.ReadAll(rw.Result().Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal(in.expectedBody))
			},
			Entry("With no override", writerFuncsTableInput{
				writer:         &WriterFuncs{},
				expectedStatus: 502,
				expectedBody:   "502 - proxy error",
			}),
			Entry("With an override function for the proxy handler", writerFuncsTableInput{
				writer: &WriterFuncs{
					ProxyErrorFunc: func(rw http.ResponseWriter, req *http.Request, proxyErr error) {
						rw.WriteHeader(503)
						rw.Write([]byte(fmt.Sprintf("%s %v", req.URL.Path, proxyErr)))
					},
				},
				expectedStatus: 503,
				expectedBody:   "/proxy proxy error",
			}),
			Entry("With an override function for the error page", writerFuncsTableInput{
				writer: &WriterFuncs{
					ErrorPageFunc: func(ctx context.Context, rw http.ResponseWriter, opts ErrorPageOpts) {
						rw.WriteHeader(500)
						rw.Write([]byte("Internal Server Error"))
					},
				},
				expectedStatus: 500,
				expectedBody:   "Internal Server Error",
			}),
		)

		DescribeTable("WriteRobotsTxt",
			func(in writerFuncsTableInput) {
				rw := httptest.NewRecorder()
				req := httptest.NewRequest("", "/robots.txt", nil)
				in.writer.WriteRobotsTxt(rw, req)

				Expect(rw.Result().StatusCode).To(Equal(in.expectedStatus))

				body, err := io.ReadAll(rw.Result().Body)
				Expect(err).ToNot(HaveOccurred())
				Expect(string(body)).To(Equal(in.expectedBody))
			},
			Entry("With no override", writerFuncsTableInput{
				writer:         &WriterFuncs{},
				expectedStatus: 200,
				expectedBody:   "Allow: *",
			}),
			Entry("With an override function", writerFuncsTableInput{
				writer: &WriterFuncs{
					RobotsTxtfunc: func(rw http.ResponseWriter, req *http.Request) {
						rw.WriteHeader(202)
						rw.Write([]byte("Disallow: *"))
					},
				},
				expectedStatus: 202,
				expectedBody:   "Disallow: *",
			}),
		)
	})
})
