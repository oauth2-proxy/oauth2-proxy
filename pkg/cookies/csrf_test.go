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
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("CSRF Cookie Tests", func() {
	var (
		cookieOpts  *options.Cookie
		publicCSRF  CSRF
		privateCSRF *csrf
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
		}

		var err error
		publicCSRF, err = NewCSRF(cookieOpts, "verifier")
		Expect(err).ToNot(HaveOccurred())

		privateCSRF = publicCSRF.(*csrf)
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
			}
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

	Context("Test Cookie SameSite", func() {
		var req *http.Request
		var cookieOpts *options.Cookie

		testNow := time.Unix(nowEpoch, 0)

		BeforeEach(func() {
			req = &http.Request{
				Method: http.MethodGet,
				Proto:  "HTTP/1.1",
				Host:   cookieDomain,

				URL: &url.URL{
					Scheme: "https",
					Host:   cookieDomain,
					Path:   cookiePath,
				},
			}

			cookieOpts = &options.Cookie{
				Name:           cookieName,
				Secret:         cookieSecret,
				Domains:        []string{cookieDomain},
				Path:           cookiePath,
				Expire:         time.Hour,
				Secure:         true,
				HTTPOnly:       true,
				CSRFPerRequest: false,
			}
		})

		It("Call SetCookie when CSRF SameSite is not defined. "+
			"Expected result: CSRF cookie SameSite is the same as session cookie.", func() {
			// prepare
			cookieOpts.SameSite = SameSiteLax
			CSRF, _ := NewCSRF(cookieOpts, "verifier")
			rw := httptest.NewRecorder()
			CSRF.(*csrf).time.Set(testNow)

			// test
			_, err := CSRF.SetCookie(rw, req)

			// validate
			Expect(err).ToNot(HaveOccurred())
			Expect(rw.Header().Get("Set-Cookie")).To(ContainSubstring(
				fmt.Sprintf(
					"; Path=%s; Domain=%s; Expires=%s; HttpOnly; Secure; SameSite=Lax",
					cookiePath,
					cookieDomain,
					testCookieExpires(testNow.Add(cookieOpts.CSRFExpire)),
				),
			))
		})

		It("Call SetCookie when CSRF SameSite is an empty string. "+
			"Expected result: CSRF cookie SameSite is the same as session cookie.", func() {
			// prepare
			cookieOpts.SameSite = SameSiteLax
			cookieOpts.CSRFSameSite = ""
			CSRF, _ := NewCSRF(cookieOpts, "verifier")
			rw := httptest.NewRecorder()
			CSRF.(*csrf).time.Set(testNow)

			// test
			_, err := CSRF.SetCookie(rw, req)

			// validate
			Expect(err).ToNot(HaveOccurred())
			Expect(rw.Header().Get("Set-Cookie")).To(ContainSubstring(
				fmt.Sprintf(
					"; Path=%s; Domain=%s; Expires=%s; HttpOnly; Secure; SameSite=Lax",
					cookiePath,
					cookieDomain,
					testCookieExpires(testNow.Add(cookieOpts.CSRFExpire)),
				),
			))
		})

		It("Call SetCookie when CSRF SameSite is 'none'. "+
			"Expected result: CSRF cookie SameSite is None.", func() {
			// prepare
			cookieOpts.SameSite = SameSiteLax
			cookieOpts.CSRFSameSite = SameSiteNone
			CSRF, _ := NewCSRF(cookieOpts, "verifier")
			rw := httptest.NewRecorder()
			CSRF.(*csrf).time.Set(testNow)

			// test
			_, err := CSRF.SetCookie(rw, req)

			// validate
			Expect(err).ToNot(HaveOccurred())
			Expect(rw.Header().Get("Set-Cookie")).To(ContainSubstring(
				fmt.Sprintf(
					"; Path=%s; Domain=%s; Expires=%s; HttpOnly; Secure; SameSite=None",
					cookiePath,
					cookieDomain,
					testCookieExpires(testNow.Add(cookieOpts.CSRFExpire)),
				),
			))
		})

		It("Call SetCookie when CSRF SameSite is 'strict'. "+
			"Expected result: CSRF cookie SameSite is Strict.", func() {
			// prepare
			cookieOpts.SameSite = SameSiteLax
			cookieOpts.CSRFSameSite = SameSiteStrict
			CSRF, _ := NewCSRF(cookieOpts, "verifier")
			rw := httptest.NewRecorder()
			CSRF.(*csrf).time.Set(testNow)

			// test
			_, err := CSRF.SetCookie(rw, req)

			// validate
			Expect(err).ToNot(HaveOccurred())
			Expect(rw.Header().Get("Set-Cookie")).To(ContainSubstring(
				fmt.Sprintf(
					"; Path=%s; Domain=%s; Expires=%s; HttpOnly; Secure; SameSite=Strict",
					cookiePath,
					cookieDomain,
					testCookieExpires(testNow.Add(cookieOpts.CSRFExpire)),
				),
			))
		})

		It("Call SetCookie when CSRF SameSite is 'lax'. "+
			"Expected result: CSRF cookie SameSite is Lax.", func() {
			// prepare
			cookieOpts.SameSite = SameSiteStrict
			cookieOpts.CSRFSameSite = SameSiteLax
			CSRF, _ := NewCSRF(cookieOpts, "verifier")
			rw := httptest.NewRecorder()
			CSRF.(*csrf).time.Set(testNow)

			// test
			_, err := CSRF.SetCookie(rw, req)

			// validate
			Expect(err).ToNot(HaveOccurred())
			Expect(rw.Header().Get("Set-Cookie")).To(ContainSubstring(
				fmt.Sprintf(
					"; Path=%s; Domain=%s; Expires=%s; HttpOnly; Secure; SameSite=Lax",
					cookiePath,
					cookieDomain,
					testCookieExpires(testNow.Add(cookieOpts.CSRFExpire)),
				),
			))
		})

		It("Call ClearCookie when CSRF SameSite is not defined. "+
			"Expected result: CSRF cookie SameSite is the same as session cookie.", func() {
			// prepare
			cookieOpts.SameSite = SameSiteLax
			CSRF, _ := NewCSRF(cookieOpts, "verifier")
			rw := httptest.NewRecorder()
			CSRF.(*csrf).time.Set(testNow)

			// test
			CSRF.ClearCookie(rw, req)

			// validate
			Expect(rw.Header().Get("Set-Cookie")).To(Equal(
				fmt.Sprintf(
					"%s=; Path=%s; Domain=%s; Expires=%s; HttpOnly; Secure; SameSite=Lax",
					CSRF.(*csrf).cookieName(),
					cookiePath,
					cookieDomain,
					testCookieExpires(testNow.Add(time.Hour*-1)),
				),
			))
		})

		It("Call ClearCookie when CSRF SameSite is an empty string. "+
			"Expected result: CSRF cookie SameSite is the same as session cookie.", func() {
			// prepare
			cookieOpts.SameSite = SameSiteLax
			cookieOpts.CSRFSameSite = ""
			CSRF, _ := NewCSRF(cookieOpts, "verifier")
			rw := httptest.NewRecorder()
			CSRF.(*csrf).time.Set(testNow)

			// test
			CSRF.ClearCookie(rw, req)

			// validate
			Expect(rw.Header().Get("Set-Cookie")).To(Equal(
				fmt.Sprintf(
					"%s=; Path=%s; Domain=%s; Expires=%s; HttpOnly; Secure; SameSite=Lax",
					CSRF.(*csrf).cookieName(),
					cookiePath,
					cookieDomain,
					testCookieExpires(testNow.Add(time.Hour*-1)),
				),
			))
		})

		It("Call ClearCookie when CSRF SameSite is 'none'. "+
			"Expected result: CSRF cookie SameSite is None.", func() {
			// prepare
			cookieOpts.SameSite = SameSiteLax
			cookieOpts.CSRFSameSite = SameSiteNone
			CSRF, _ := NewCSRF(cookieOpts, "verifier")
			rw := httptest.NewRecorder()
			CSRF.(*csrf).time.Set(testNow)

			// test
			CSRF.ClearCookie(rw, req)

			// validate
			Expect(rw.Header().Get("Set-Cookie")).To(Equal(
				fmt.Sprintf(
					"%s=; Path=%s; Domain=%s; Expires=%s; HttpOnly; Secure; SameSite=None",
					CSRF.(*csrf).cookieName(),
					cookiePath,
					cookieDomain,
					testCookieExpires(testNow.Add(time.Hour*-1)),
				),
			))
		})

		It("Call ClearCookie when CSRF SameSite is 'strict'. "+
			"Expected result: CSRF cookie SameSite is Strict.", func() {
			// prepare
			cookieOpts.SameSite = SameSiteLax
			cookieOpts.CSRFSameSite = SameSiteStrict
			CSRF, _ := NewCSRF(cookieOpts, "verifier")
			rw := httptest.NewRecorder()
			CSRF.(*csrf).time.Set(testNow)

			// test
			CSRF.ClearCookie(rw, req)

			// validate
			Expect(rw.Header().Get("Set-Cookie")).To(Equal(
				fmt.Sprintf(
					"%s=; Path=%s; Domain=%s; Expires=%s; HttpOnly; Secure; SameSite=Strict",
					CSRF.(*csrf).cookieName(),
					cookiePath,
					cookieDomain,
					testCookieExpires(testNow.Add(time.Hour*-1)),
				),
			))
		})

		It("Call ClearCookie when CSRF SameSite is 'lax'. "+
			"Expected result: CSRF cookie SameSite is Lax.", func() {
			// prepare
			cookieOpts.SameSite = SameSiteStrict
			cookieOpts.CSRFSameSite = SameSiteLax
			CSRF, _ := NewCSRF(cookieOpts, "verifier")
			rw := httptest.NewRecorder()
			CSRF.(*csrf).time.Set(testNow)

			// test
			CSRF.ClearCookie(rw, req)

			// validate
			Expect(rw.Header().Get("Set-Cookie")).To(Equal(
				fmt.Sprintf(
					"%s=; Path=%s; Domain=%s; Expires=%s; HttpOnly; Secure; SameSite=Lax",
					CSRF.(*csrf).cookieName(),
					cookiePath,
					cookieDomain,
					testCookieExpires(testNow.Add(time.Hour*-1)),
				),
			))
		})
	})
})
