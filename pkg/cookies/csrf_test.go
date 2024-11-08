package cookies

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
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
			Name:           cookieName,
			Secret:         cookieSecret,
			Domains:        []string{cookieDomain},
			Path:           cookiePath,
			Expire:         time.Hour,
			Secure:         true,
			HTTPOnly:       true,
			CSRFPerRequest: false,
			CSRFExpire:     time.Hour,
		}

		var err error
		publicCSRF, err = NewCSRF(cookieOpts, "verifier")
		Expect(err).ToNot(HaveOccurred())

		privateCSRF = publicCSRF.(*csrf)
		csrfName = GenerateCookieName(cookieOpts, csrfNonce)
	})

	Context("NewCSRF", func() {
		It("makes unique nonces for OAuth and OIDC", func() {
			Expect(privateCSRF.OAuthState).ToNot(BeEmpty())
			Expect(privateCSRF.OIDCNonce).ToNot(BeEmpty())
			Expect(privateCSRF.OAuthState).ToNot(Equal(privateCSRF.OIDCNonce))
			Expect(privateCSRF.CodeVerifier).To(Equal("verifier"))
		})

		It("makes unique nonces between multiple CSRFs", func() {
			other, err := NewCSRF(cookieOpts, "verifier")
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

	Context("encodeCookie and decodeCSRFCookie", func() {
		It("encodes and decodes to the same nonces", func() {
			privateCSRF.OAuthState = []byte(csrfState)
			privateCSRF.OIDCNonce = []byte(csrfNonce)

			encoded, err := privateCSRF.encodeCookie()
			Expect(err).ToNot(HaveOccurred())

			cookie := &http.Cookie{
				Name:  privateCSRF.cookieName(),
				Value: encoded,
			}
			decoded, err := decodeCSRFCookie(cookie, cookieOpts)
			Expect(err).ToNot(HaveOccurred())

			Expect(decoded).ToNot(BeNil())
			Expect(decoded.OAuthState).To(Equal([]byte(csrfState)))
			Expect(decoded.OIDCNonce).To(Equal([]byte(csrfNonce)))
		})

		It("signs the encoded cookie value", func() {
			encoded, err := privateCSRF.encodeCookie()
			Expect(err).ToNot(HaveOccurred())

			cookie := &http.Cookie{
				Name:  privateCSRF.cookieName(),
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
				Host:   cookieDomain,

				URL: &url.URL{
					Scheme: "https",
					Host:   cookieDomain,
					Path:   cookiePath,
				},
				Header: make(http.Header)}
		})

		AfterEach(func() {
			privateCSRF.time.Reset()
		})

		Context("SetCookie", func() {
			It("adds the encoded CSRF cookie to a ResponseWriter", func() {
				rw := httptest.NewRecorder()

				_, err := publicCSRF.SetCookie(rw, req)
				Expect(err).ToNot(HaveOccurred())

				Expect(rw.Header().Get("Set-Cookie")).To(ContainSubstring(
					fmt.Sprintf("%s=", privateCSRF.cookieName()),
				))
				Expect(rw.Header().Get("Set-Cookie")).To(ContainSubstring(
					fmt.Sprintf(
						"; Path=%s; Domain=%s; Expires=%s; HttpOnly; Secure",
						cookiePath,
						cookieDomain,
						testCookieExpires(testNow.Add(cookieOpts.CSRFExpire)),
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
				privateCSRF.OAuthState = []byte(csrfState)
				privateCSRF.OIDCNonce = []byte(csrfNonce)
				encoded, err := privateCSRF.encodeCookie()
				Expect(err).ToNot(HaveOccurred())

				req.AddCookie(&http.Cookie{
					Name:  privateCSRF.cookieName(),
					Value: encoded,
				})

				csrf, err := LoadCSRFCookie(req, csrfName, cookieOpts)
				Expect(err).ToNot(HaveOccurred())
				Expect(csrf).ToNot(BeNil())
			})

			It("should return error when one invalid cookie is set", func() {
				req.AddCookie(&http.Cookie{
					Name:  privateCSRF.cookieName(),
					Value: "invalid",
				})

				csrf, err := LoadCSRFCookie(req, csrfName, cookieOpts)
				Expect(err).To(HaveOccurred())
				Expect(csrf).To(BeNil())
			})

			It("should be able to handle two cookie with one invalid", func() {
				privateCSRF.OAuthState = []byte(csrfState)
				privateCSRF.OIDCNonce = []byte(csrfNonce)
				encoded, err := privateCSRF.encodeCookie()
				Expect(err).ToNot(HaveOccurred())

				req.AddCookie(&http.Cookie{
					Name:  privateCSRF.cookieName(),
					Value: "invalid",
				})

				req.AddCookie(&http.Cookie{
					Name:  privateCSRF.cookieName(),
					Value: encoded,
				})

				csrf, err := LoadCSRFCookie(req, csrfName, cookieOpts)
				Expect(err).ToNot(HaveOccurred())
				Expect(csrf).ToNot(BeNil())
			})
		})

		Context("ClearCookie", func() {
			It("sets a cookie with an empty value in the past", func() {
				rw := httptest.NewRecorder()

				publicCSRF.ClearCookie(rw, req)

				Expect(rw.Header().Get("Set-Cookie")).To(Equal(
					fmt.Sprintf(
						"%s=; Path=%s; Domain=%s; Expires=%s; HttpOnly; Secure",
						privateCSRF.cookieName(),
						cookiePath,
						cookieDomain,
						testCookieExpires(testNow.Add(time.Hour*-1)),
					),
				))
			})
		})

		Context("cookieName", func() {
			It("has the cookie options name as a base", func() {
				Expect(privateCSRF.cookieName()).To(ContainSubstring(cookieName))
			})
		})
	})
})
