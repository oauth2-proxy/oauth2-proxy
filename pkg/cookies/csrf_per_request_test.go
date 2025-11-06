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
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("CSRF Cookie with non-fixed name Tests", func() {
	var (
		cookieOpts  *options.Cookie
		publicCSRF  CSRF
		privateCSRF *csrf
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
			CSRFPerRequest:  true,
			CSRFExpire:      time.Duration(5) * time.Minute,
		}

		var err error
		ctx := context.Background()

		err = cookieOpts.Init()
		Expect(err).ToNot(HaveOccurred())

		publicCSRF, err = NewCSRF(ctx, cookieOpts, "verifier")
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
			}
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

		Context("CSRF per request limit", func() {
			It("clears cookies based on the limit", func() {
				ctx := context.Background()
				// needs to be now as pkg/encryption/utils.go uses time.Now()
				testNow := time.Now()
				cookieOpts.CSRFPerRequestLimit = 1

				publicCSRF1, err := NewCSRF(ctx, cookieOpts, "verifier")
				Expect(err).ToNot(HaveOccurred())
				privateCSRF1 := publicCSRF1.(*csrf)
				privateCSRF1.time.Set(testNow)

				publicCSRF2, err := NewCSRF(ctx, cookieOpts, "verifier")
				Expect(err).ToNot(HaveOccurred())
				privateCSRF2 := publicCSRF2.(*csrf)
				privateCSRF2.time.Set(testNow.Add(time.Minute))

				publicCSRF3, err := NewCSRF(ctx, cookieOpts, "verifier")
				Expect(err).ToNot(HaveOccurred())
				privateCSRF3 := publicCSRF3.(*csrf)
				privateCSRF3.time.Set(testNow.Add(time.Minute * 2))

				cookies := []string{}
				for _, csrf := range []*csrf{privateCSRF1, privateCSRF2, privateCSRF3} {
					encoded, err := csrf.encodeCookie(ctx)
					Expect(err).ToNot(HaveOccurred())
					cookie := MakeCookieFromOptions(
						req,
						csrf.cookieName(ctx),
						encoded,
						csrf.cookieOpts,
						csrf.cookieOpts.CSRFExpire,
					)
					cookies = append(cookies, fmt.Sprintf("%v=%v", cookie.Name, cookie.Value))
				}

				header := make(map[string][]string, 1)
				header["Cookie"] = cookies
				req = &http.Request{
					Method: http.MethodGet,
					Proto:  "HTTP/1.1",
					Host:   cookieDomainTemplate,

					URL: &url.URL{
						Scheme: "https",
						Host:   cookieDomainTemplate,
						Path:   cookiePath,
					},
					Header: header,
				}

				// when setting the limit to one csrf cookie but configuring three csrf cookies
				// then two cookies should be removed / set to expired on the response

				// for this test case we have set all the cookies on a single request,
				// but in reality this will be multiple requests after another
				rw := httptest.NewRecorder()
				ClearExtraCsrfCookies(cookieOpts, rw, req)

				clearedCookies := rw.Header()["Set-Cookie"]
				Expect(clearedCookies).To(HaveLen(2))
				Expect(clearedCookies[0]).To(Equal(
					fmt.Sprintf(
						"%s=; Path=%s; Domain=%s; Max-Age=0; HttpOnly; Secure",
						privateCSRF1.cookieName(ctx),
						cookiePath,
						cookieDomainTemplate,
					),
				))
				Expect(clearedCookies[1]).To(Equal(
					fmt.Sprintf(
						"%s=; Path=%s; Domain=%s; Max-Age=0; HttpOnly; Secure",
						privateCSRF2.cookieName(ctx),
						cookiePath,
						cookieDomainTemplate,
					),
				))
			})
		})
	})
})
