package cookies

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers/utils"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CSRF Cookie Tests", func() {
	var (
		cookieOpts  *options.Cookie
		publicCSRF  CSRF
		privateCSRF *csrf
		csrfName    string
	)

	BeforeEach(func() {
		cookieOpts = &options.Cookie{
			Name:            cookieName,
			Secret:          cookieSecret,
			DomainTemplates: []string{cookieDomainTemplate},
			Path:            cookiePath,
			Expire:          time.Hour,
			Secure:          true,
			HTTPOnly:        true,
			CSRFPerRequest:  false,
			CSRFExpire:      time.Hour,
		}

		var err error
		ctx := context.Background()
		ctx = utils.AppendProviderIDToContext(ctx, "dummy")
		req := &http.Request{
			Method: http.MethodGet,
			Proto:  "HTTP/1.1",
			Host:   cookieDomainTemplate,

			URL: &url.URL{
				Scheme: "https",
				Host:   cookieDomainTemplate,
				Path:   cookiePath,
			},
		}

		err = cookieOpts.Init()
		Expect(err).ToNot(HaveOccurred())

		publicCSRF, err = NewCSRF(ctx, cookieOpts, "verifier")
		Expect(err).ToNot(HaveOccurred())

		privateCSRF = publicCSRF.(*csrf)
		csrfName = GenerateCookieName(req, cookieOpts, csrfNonce)
	})

	Context("NewCSRF", func() {
		It("makes unique nonces for OAuth and OIDC", func() {
			Expect(privateCSRF.OAuthState).ToNot(BeEmpty())
			Expect(privateCSRF.OIDCNonce).ToNot(BeEmpty())
			Expect(privateCSRF.OAuthState).ToNot(Equal(privateCSRF.OIDCNonce))
			Expect(privateCSRF.CodeVerifier).To(Equal("verifier"))
			Expect(privateCSRF.ProviderID).To(Equal("dummy"))
		})

		It("makes unique nonces between multiple CSRFs", func() {
			ctx := context.Background()
			other, err := NewCSRF(ctx, cookieOpts, "verifier")
			Expect(err).ToNot(HaveOccurred())

			Expect(privateCSRF.OAuthState).ToNot(Equal(other.(*csrf).OAuthState))
			Expect(privateCSRF.OIDCNonce).ToNot(Equal(other.(*csrf).OIDCNonce))
			Expect(privateCSRF.CodeVerifier).To(Equal("verifier"))
		})
	})

	Context("CheckOAuthState and CheckOIDCNonce", func() {
		It("checks that hashed versions match", func() {
			privateCSRF.OAuthState = []byte(csrfState)
			privateCSRF.OIDCNonce = []byte(csrfNonce)

			stateHashed := encryption.HashNonce([]byte(csrfState))
			nonceHashed := encryption.HashNonce([]byte(csrfNonce))

			Expect(publicCSRF.CheckOAuthState(stateHashed)).To(BeTrue())
			Expect(publicCSRF.CheckOIDCNonce(nonceHashed)).To(BeTrue())

			Expect(publicCSRF.CheckOAuthState(csrfNonce)).To(BeFalse())
			Expect(publicCSRF.CheckOIDCNonce(csrfState)).To(BeFalse())
			Expect(publicCSRF.CheckOAuthState(csrfState + csrfNonce)).To(BeFalse())
			Expect(publicCSRF.CheckOIDCNonce(csrfNonce + csrfState)).To(BeFalse())
			Expect(publicCSRF.CheckOAuthState("")).To(BeFalse())
			Expect(publicCSRF.CheckOIDCNonce("")).To(BeFalse())
			Expect(publicCSRF.GetCodeVerifier()).To(Equal("verifier"))
		})
	})

	Context("SetSessionNonce", func() {
		It("sets the session.Nonce", func() {
			session := &sessions.SessionState{}
			publicCSRF.SetSessionNonce(session)
			Expect(session.Nonce).To(Equal(privateCSRF.OIDCNonce))
		})
	})

	Context("Load cookie", func() {
		var req *http.Request

		BeforeEach(func() {
			req = &http.Request{
				Method: http.MethodGet,
				Proto:  "HTTP/1.1",
				Host:   cookieDomainTemplate,

				URL: &url.URL{
					Scheme: "https",
					Host:   cookieDomainTemplate,
					Path:   cookiePath,
				},
			}
		})

		It("with different providerid", func(ctx SpecContext) {
			privateCSRF.OAuthState = []byte(csrfState)
			privateCSRF.OIDCNonce = []byte(csrfNonce)

			encoded, err := privateCSRF.encodeCookie(ctx)
			Expect(err).ToNot(HaveOccurred())

			cookie := &http.Cookie{
				Name:  privateCSRF.cookieName(ctx),
				Value: encoded,
			}

			req.Header = http.Header{}
			req.AddCookie(cookie)
			_, err = LoadCSRFCookie(req, cookie.Name, cookieOpts)
			Expect(err).To(Equal(fmt.Errorf("CSRF cookie with name '%s' was not found or providerID in cookie is not same as in the context", cookie.Name)))
		})

		It("with same providerID", func(c SpecContext) {
			ctx := utils.AppendProviderIDToContext(req.Context(), "dummy")
			privateCSRF.OAuthState = []byte(csrfState)
			privateCSRF.OIDCNonce = []byte(csrfNonce)

			encoded, err := privateCSRF.encodeCookie(ctx)
			Expect(err).ToNot(HaveOccurred())

			cookie := &http.Cookie{
				Name:  privateCSRF.cookieName(ctx),
				Value: encoded,
			}

			newReq := req.WithContext(ctx)
			newReq.Header = http.Header{}
			newReq.AddCookie(cookie)
			_, err = LoadCSRFCookie(newReq, cookie.Name, cookieOpts)
			Expect(err).ToNot(HaveOccurred())

		})
	})

	Context("encodeCookie and decodeCSRFCookie", func() {
		It("encodes and decodes to the same nonces", func(ctx SpecContext) {
			privateCSRF.OAuthState = []byte(csrfState)
			privateCSRF.OIDCNonce = []byte(csrfNonce)

			encoded, err := privateCSRF.encodeCookie(ctx)
			Expect(err).ToNot(HaveOccurred())

			cookie := &http.Cookie{
				Name:  privateCSRF.cookieName(ctx),
				Value: encoded,
			}
			decoded, err := decodeCSRFCookie(cookie, cookieOpts)
			Expect(err).ToNot(HaveOccurred())

			Expect(decoded).ToNot(BeNil())
			Expect(decoded.OAuthState).To(Equal([]byte(csrfState)))
			Expect(decoded.OIDCNonce).To(Equal([]byte(csrfNonce)))
		})

		It("signs the encoded cookie value", func(ctx SpecContext) {
			encoded, err := privateCSRF.encodeCookie(ctx)
			Expect(err).ToNot(HaveOccurred())

			cookie := &http.Cookie{
				Name:  privateCSRF.cookieName(ctx),
				Value: encoded,
			}

			_, _, valid := encryption.Validate(cookie, cookieOpts.Secret, cookieOpts.Expire)
			Expect(valid).To(BeTrue())
		})
	})

	Context("Cookie Management", func() {
		var req *http.Request

		testNow := time.Unix(nowEpoch, 0)

		BeforeEach(func() {
			privateCSRF.time.Set(testNow)

			req = &http.Request{
				Method: http.MethodGet,
				Proto:  "HTTP/1.1",
				Host:   cookieDomainTemplate,

				URL: &url.URL{
					Scheme: "https",
					Host:   cookieDomainTemplate,
					Path:   cookiePath,
				},
				Header: make(http.Header)}
		})

		AfterEach(func() {
			privateCSRF.time.Reset()
		})

		Context("SetCookie", func() {
			It("adds the encoded CSRF cookie to a ResponseWriter", func(ctx SpecContext) {
				rw := httptest.NewRecorder()

				_, err := publicCSRF.SetCookie(rw, req)
				Expect(err).ToNot(HaveOccurred())

				Expect(rw.Header().Get("Set-Cookie")).To(ContainSubstring(
					fmt.Sprintf("%s=", privateCSRF.cookieName(ctx)),
				))
				Expect(rw.Header().Get("Set-Cookie")).To(ContainSubstring(
					fmt.Sprintf(
						"; Path=%s; Domain=%s; Max-Age=%d; HttpOnly; Secure",
						cookiePath,
						cookieDomainTemplate,
						int(cookieOpts.CSRFExpire.Seconds()),
					),
				))
			})
		})

		Context("LoadCSRFCookie", func() {
			BeforeEach(func() {
				// we need to reset the time to ensure the cookie is valid
				privateCSRF.time.Reset()
			})

			It("should return error when no cookie is set", func() {
				csrf, err := LoadCSRFCookie(req, csrfName, cookieOpts)
				Expect(err).To(HaveOccurred())
				Expect(csrf).To(BeNil())
			})

			It("should find one valid cookie", func() {
				ctx := context.Background()
				ctx = utils.AppendProviderIDToContext(ctx, "dummy")

				newReq := req.WithContext(ctx)
				privateCSRF.OAuthState = []byte(csrfState)
				privateCSRF.OIDCNonce = []byte(csrfNonce)
				encoded, err := privateCSRF.encodeCookie(req.Context())
				Expect(err).ToNot(HaveOccurred())

				cookie := &http.Cookie{
					Name:  privateCSRF.cookieName(req.Context()),
					Value: encoded,
				}

				newReq.AddCookie(cookie)

				csrf, err := LoadCSRFCookie(newReq, cookie.Name, cookieOpts)
				Expect(err).ToNot(HaveOccurred())
				Expect(csrf).ToNot(BeNil())
			})

			It("should return error when one invalid cookie is set", func() {
				req.AddCookie(&http.Cookie{
					Name:  privateCSRF.cookieName(req.Context()),
					Value: "invalid",
				})

				csrf, err := LoadCSRFCookie(req, csrfName, cookieOpts)
				Expect(err).To(HaveOccurred())
				Expect(csrf).To(BeNil())
			})

			It("should be able to handle two cookie with one invalid", func() {
				privateCSRF.OAuthState = []byte(csrfState)
				privateCSRF.OIDCNonce = []byte(csrfNonce)
				encoded, err := privateCSRF.encodeCookie(req.Context())
				Expect(err).ToNot(HaveOccurred())

				ctx := context.Background()
				ctx = utils.AppendProviderIDToContext(ctx, "dummy")

				newReq := req.WithContext(ctx)

				newReq.AddCookie(&http.Cookie{
					Name:  privateCSRF.cookieName(req.Context()),
					Value: "invalid",
				})

				newReq.AddCookie(&http.Cookie{
					Name:  privateCSRF.cookieName(req.Context()),
					Value: encoded,
				})

				csrf, err := LoadCSRFCookie(newReq, csrfName, cookieOpts)
				Expect(err).ToNot(HaveOccurred())
				Expect(csrf).ToNot(BeNil())
			})
		})

		Context("ClearCookie", func() {
			It("sets a cookie with an empty value in the past", func(ctx SpecContext) {
				rw := httptest.NewRecorder()
				publicCSRF.ClearCookie(rw, req)

				Expect(rw.Header().Get("Set-Cookie")).To(Equal(
					fmt.Sprintf(
						"%s=; Path=%s; Domain=%s; Max-Age=0; HttpOnly; Secure",
						privateCSRF.cookieName(ctx),
						cookiePath,
						cookieDomainTemplate,
					),
				))
			})
		})

		Context("cookieName", func() {
			It("has the cookie options name as a base", func(ctx SpecContext) {
				Expect(privateCSRF.cookieName(ctx)).To(ContainSubstring(cookieName))
			})
		})
	})
})
