package providers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	internaloidc "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/oidc"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type fakeADFSJwks struct{}

func (fakeADFSJwks) VerifySignature(_ context.Context, jwt string) (payload []byte, err error) {
	decodeString, err := base64.RawURLEncoding.DecodeString(strings.Split(jwt, ".")[1])
	if err != nil {
		return nil, err
	}
	return decodeString, nil
}

type adfsClaims struct {
	UPN string `json:"upn,omitempty"`
	idTokenClaims
}

func newSignedTestADFSToken(tokenClaims adfsClaims) (string, error) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	standardClaims := jwt.NewWithClaims(jwt.SigningMethodRS256, tokenClaims)
	return standardClaims.SignedString(key)
}

func testADFSProvider(hostname string) *ADFSProvider {
	verificationOptions := internaloidc.IDTokenVerificationOptions{
		AudienceClaims: []string{"aud"},
		ClientID:       "https://test.myapp.com",
	}

	o := internaloidc.NewVerifier(oidc.NewVerifier(
		"https://issuer.example.com",
		fakeADFSJwks{},
		&oidc.Config{ClientID: "https://test.myapp.com"},
	), verificationOptions)

	p := NewADFSProvider(&ProviderData{
		ProviderName: "",
		LoginURL:     &url.URL{},
		RedeemURL:    &url.URL{},
		ProfileURL:   &url.URL{},
		ValidateURL:  &url.URL{},
		Scope:        "",
		Verifier:     o,
		EmailClaim:   options.OIDCEmailClaim,
	}, options.Provider{})

	if hostname != "" {
		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		updateURL(p.Data().ProfileURL, hostname)
		updateURL(p.Data().ValidateURL, hostname)
	}

	return p
}

func testADFSBackend() *httptest.Server {
	authResponse := `
		{
			"access_token": "my_access_token",
			"id_token": "my_id_token",
			"refresh_token": "my_refresh_token"
		 }
	`
	userInfo := `
		{
			"email": "samiracho@email.com"
		}
	`

	refreshResponse := `{ "access_token": "new_some_access_token", "refresh_token": "new_some_refresh_token", "expires_in": "32693148245", "id_token": "new_some_id_token" }`

	authHeader := "Bearer adfs_access_token"

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/adfs/oauth2/authorize":
				w.WriteHeader(200)
				w.Write([]byte(authResponse))
			case "/adfs/oauth2/refresh":
				w.WriteHeader(200)
				w.Write([]byte(refreshResponse))
			case "/adfs/oauth2/userinfo":
				if r.Header["Authorization"][0] == authHeader {
					w.WriteHeader(200)
					w.Write([]byte(userInfo))
				} else {
					w.WriteHeader(401)
				}
			default:
				w.WriteHeader(200)
			}
		}))
}

var _ = Describe("ADFS Provider Tests", func() {
	var p *ADFSProvider
	var b *httptest.Server

	BeforeEach(func() {
		b = testADFSBackend()

		bURL, err := url.Parse(b.URL)
		Expect(err).To(BeNil())

		p = testADFSProvider(bURL.Host)
	})

	AfterEach(func() {
		b.Close()
	})

	Context("New Provider Init", func() {
		It("uses defaults", func() {
			providerData := NewADFSProvider(&ProviderData{}, options.Provider{}).Data()
			Expect(providerData.ProviderName).To(Equal("ADFS"))
			Expect(providerData.Scope).To(Equal(oidcDefaultScope))
		})
		It("uses custom scope", func() {
			providerData := NewADFSProvider(&ProviderData{Scope: "openid email"}, options.Provider{}).Data()
			Expect(providerData.ProviderName).To(Equal("ADFS"))
			Expect(providerData.Scope).To(Equal("openid email"))
			Expect(providerData.Scope).NotTo(Equal(oidcDefaultScope))
		})
	})

	Context("with bad token", func() {
		It("should trigger an error", func() {
			session := &sessions.SessionState{AccessToken: "unexpected_adfs_access_token", IDToken: "malformed_token"}
			err := p.EnrichSession(context.Background(), session)
			Expect(err).NotTo(BeNil())
		})
	})

	Context("with valid token", func() {
		It("should not throw an error", func() {
			rawIDToken, _ := newSignedTestIDToken(defaultIDToken)
			session, err := p.buildSessionFromClaims(rawIDToken, "")
			Expect(err).To(BeNil())
			session.IDToken = rawIDToken
			err = p.EnrichSession(context.Background(), session)
			Expect(session.Email).To(Equal("janed@me.com"))
			Expect(err).To(BeNil())
		})
	})

	Context("with skipScope enabled", func() {
		It("should not include parameter scope", func() {
			resource, _ := url.Parse("http://example.com")
			p := NewADFSProvider(&ProviderData{
				ProtectedResource: resource,
				Scope:             "",
			}, options.Provider{
				ADFSConfig: options.ADFSOptions{SkipScope: true},
			})

			result := p.GetLoginURL("https://example.com/adfs/oauth2/", "", "", url.Values{})
			Expect(result).NotTo(ContainSubstring("scope="))
		})
	})

	Context("With resource parameter", func() {
		type scopeTableInput struct {
			resource      string
			scope         string
			expectedScope string
		}

		DescribeTable("should return expected results",
			func(in scopeTableInput) {
				resource, _ := url.Parse(in.resource)
				p := NewADFSProvider(&ProviderData{
					ProtectedResource: resource,
					Scope:             in.scope,
				}, options.Provider{})

				Expect(p.Data().Scope).To(Equal(in.expectedScope))
				result := p.GetLoginURL("https://example.com/adfs/oauth2/", "", "", url.Values{})
				Expect(result).To(ContainSubstring("scope=" + url.QueryEscape(in.expectedScope)))
			},
			Entry("should add slash", scopeTableInput{
				resource:      "http://resource.com",
				scope:         "openid",
				expectedScope: "http://resource.com/openid",
			}),
			Entry("shouldn't add extra slash", scopeTableInput{
				resource:      "http://resource.com/",
				scope:         "openid",
				expectedScope: "http://resource.com/openid",
			}),
			Entry("should add default scopes with resource", scopeTableInput{
				resource:      "http://resource.com/",
				scope:         "",
				expectedScope: "http://resource.com/openid email profile",
			}),
			Entry("should add default scopes", scopeTableInput{
				resource:      "",
				scope:         "",
				expectedScope: "openid email profile",
			}),
			Entry("shouldn't add resource if already in scopes", scopeTableInput{
				resource:      "http://resource.com",
				scope:         "http://resource.com/openid",
				expectedScope: "http://resource.com/openid",
			}),
		)
	})

	Context("UPN Fallback", func() {
		var idToken string
		var session *sessions.SessionState

		BeforeEach(func() {
			var err error
			idToken, err = newSignedTestADFSToken(adfsClaims{
				UPN:           "upn@company.com",
				idTokenClaims: minimalIDToken,
			})
			Expect(err).ToNot(HaveOccurred())

			session = &sessions.SessionState{
				IDToken: idToken,
			}
		})

		Describe("EnrichSession", func() {
			It("uses email claim if present", func() {
				p.oidcEnrichFunc = func(_ context.Context, s *sessions.SessionState) error {
					s.Email = "person@company.com"
					return nil
				}

				err := p.EnrichSession(context.Background(), session)
				Expect(err).ToNot(HaveOccurred())
				Expect(session.Email).To(Equal("person@company.com"))
			})

			It("falls back to UPN claim if Email is missing", func() {
				p.oidcEnrichFunc = func(_ context.Context, s *sessions.SessionState) error {
					return nil
				}

				err := p.EnrichSession(context.Background(), session)
				Expect(err).ToNot(HaveOccurred())
				Expect(session.Email).To(Equal("upn@company.com"))
			})

			It("falls back to UPN claim on errors", func() {
				p.oidcEnrichFunc = func(_ context.Context, s *sessions.SessionState) error {
					return errors.New("neither the id_token nor the profileURL set an email")
				}

				err := p.EnrichSession(context.Background(), session)
				Expect(err).ToNot(HaveOccurred())
				Expect(session.Email).To(Equal("upn@company.com"))
			})
		})

		Describe("RefreshSession", func() {
			It("uses email claim if present", func() {
				p.oidcRefreshFunc = func(_ context.Context, s *sessions.SessionState) (bool, error) {
					s.Email = "person@company.com"
					return true, nil
				}

				_, err := p.RefreshSession(context.Background(), session)
				Expect(err).ToNot(HaveOccurred())
				Expect(session.Email).To(Equal("person@company.com"))
			})

			It("falls back to UPN claim if Email is missing", func() {
				p.oidcRefreshFunc = func(_ context.Context, s *sessions.SessionState) (bool, error) {
					return true, nil
				}

				_, err := p.RefreshSession(context.Background(), session)
				Expect(err).ToNot(HaveOccurred())
				Expect(session.Email).To(Equal("upn@company.com"))
			})
		})
	})
})
