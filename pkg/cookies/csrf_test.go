package cookies

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("CSRF Cookie Tests", func() {
	var (
		csrf       *CSRF
		cookieOpts *options.Cookie
	)

	BeforeEach(func() {
		cookieOpts = &options.Cookie{
			Name:     cookieName,
			Secret:   cookieSecret,
			Domains:  []string{cookieDomain},
			Path:     cookiePath,
			Expire:   time.Hour,
			Secure:   true,
			HTTPOnly: true,
		}

		var err error
		csrf, err = NewCSRF(cookieOpts)
		Expect(err).ToNot(HaveOccurred())
	})

	Context("NewCSRF", func() {
		It("makes unique nonces for OAuth and OIDC", func() {
			Expect(csrf.OAuthState).ToNot(BeEmpty())
			Expect(csrf.OIDCNonce).ToNot(BeEmpty())
			Expect(csrf.OAuthState).ToNot(Equal(csrf.OIDCNonce))
		})

		It("makes unique nonces between multiple CSRFs", func() {
			other, err := NewCSRF(cookieOpts)
			Expect(err).ToNot(HaveOccurred())

			Expect(csrf.OAuthState).ToNot(Equal(other.OAuthState))
			Expect(csrf.OIDCNonce).ToNot(Equal(other.OIDCNonce))
		})
	})

	Context("CheckOAuthState and CheckOIDCNonce", func() {
		It("checks that hashed versions match", func() {
			csrf.OAuthState = []byte(csrfState)
			csrf.OIDCNonce = []byte(csrfNonce)

			stateHashed := encryption.HashNonce([]byte(csrfState))
			nonceHashed := encryption.HashNonce([]byte(csrfNonce))

			Expect(csrf.CheckOAuthState(stateHashed)).To(BeTrue())
			Expect(csrf.CheckOIDCNonce(nonceHashed)).To(BeTrue())

			Expect(csrf.CheckOAuthState(csrfNonce)).To(BeFalse())
			Expect(csrf.CheckOIDCNonce(csrfState)).To(BeFalse())
			Expect(csrf.CheckOAuthState(csrfState + csrfNonce)).To(BeFalse())
			Expect(csrf.CheckOIDCNonce(csrfNonce + csrfState)).To(BeFalse())
			Expect(csrf.CheckOAuthState("")).To(BeFalse())
			Expect(csrf.CheckOIDCNonce("")).To(BeFalse())
		})
	})

	Context("CookieName", func() {
		It("has the cookie options name as a base", func() {
			Expect(csrf.CookieName()).To(ContainSubstring(cookieName))
		})
	})

	Context("EncodeCookie and DecodeCSRFCookie", func() {
		It("encodes and decodes to the same nonces", func() {
			csrf.OAuthState = []byte(csrfState)
			csrf.OIDCNonce = []byte(csrfNonce)

			encoded, err := csrf.EncodeCookie()
			Expect(err).ToNot(HaveOccurred())

			cookie := &http.Cookie{
				Name:  csrf.CookieName(),
				Value: encoded,
			}
			decoded, err := DecodeCSRFCookie(cookie, cookieOpts)
			Expect(err).ToNot(HaveOccurred())

			Expect(decoded).ToNot(BeNil())
			Expect(decoded.OAuthState).To(Equal([]byte(csrfState)))
			Expect(decoded.OIDCNonce).To(Equal([]byte(csrfNonce)))
		})

		It("signs the encoded cookie value", func() {
			encoded, err := csrf.EncodeCookie()
			Expect(err).ToNot(HaveOccurred())

			cookie := &http.Cookie{
				Name:  csrf.CookieName(),
				Value: encoded,
			}

			_, _, valid := encryption.Validate(cookie, cookieOpts.Secret, cookieOpts.Expire)
			Expect(valid).To(BeTrue())
		})
	})

	Context("Cookie Management", func() {
		var req *http.Request

		BeforeEach(func() {
			now = func() time.Time {
				return time.Unix(nowEpoch, 0)
			}

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

		Context("SetCookie", func() {
			It("adds the encoded CSRF cookie to a ResponseWriter", func() {
				rw := httptest.NewRecorder()

				err := csrf.SetCookie(rw, req)
				Expect(err).ToNot(HaveOccurred())

				Expect(rw.Header().Get("Set-Cookie")).To(ContainSubstring(
					fmt.Sprintf("%s=", csrf.CookieName()),
				))
				Expect(rw.Header().Get("Set-Cookie")).To(ContainSubstring(
					fmt.Sprintf(
						"; Path=%s; Domain=%s; Expires=%s; HttpOnly; Secure; SameSite",
						cookiePath,
						cookieDomain,
						testCookieExpires(now().Add(cookieOpts.Expire)),
					),
				))
			})
		})

		Context("ClearCookie", func() {
			It("sets a cookie with an empty value in the past", func() {
				rw := httptest.NewRecorder()

				csrf.ClearCookie(rw, req)

				Expect(rw.Header().Get("Set-Cookie")).To(Equal(
					fmt.Sprintf(
						"%s=; Path=%s; Domain=%s; Expires=%s; HttpOnly; Secure; SameSite",
						csrf.CookieName(),
						cookiePath,
						cookieDomain,
						testCookieExpires(now().Add(time.Hour*-1)),
					),
				))
			})
		})
	})
})
