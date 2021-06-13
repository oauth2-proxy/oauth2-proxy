package providers

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
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

func testADFSProvider(hostname string) *ADFSProvider {

	o := oidc.NewVerifier(
		"https://issuer.example.com",
		fakeADFSJwks{},
		&oidc.Config{ClientID: "https://test.myapp.com"},
	)

	p := NewADFSProvider(&ProviderData{
		ProviderName: "",
		LoginURL:     &url.URL{},
		RedeemURL:    &url.URL{},
		ProfileURL:   &url.URL{},
		ValidateURL:  &url.URL{},
		Scope:        "",
		Verifier:     o,
	})

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
			providerData := NewADFSProvider(&ProviderData{}).Data()
			Expect(providerData.ProviderName).To(Equal("ADFS"))
			Expect(providerData.Scope).To(Equal("openid email profile"))
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
			p.EmailClaim = "email"
			rawIDToken, _ := newSignedTestIDToken(defaultIDToken)
			idToken, err := p.Verifier.Verify(context.Background(), rawIDToken)
			Expect(err).To(BeNil())
			session, err := p.buildSessionFromClaims(idToken)
			session.IDToken = rawIDToken
			Expect(err).To(BeNil())
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
			})
			p.SkipScope = true

			result := p.GetLoginURL("https://example.com/adfs/oauth2/", "", "")
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
				})

				Expect(p.Data().Scope).To(Equal(in.expectedScope))
				result := p.GetLoginURL("https://example.com/adfs/oauth2/", "", "")
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
})
