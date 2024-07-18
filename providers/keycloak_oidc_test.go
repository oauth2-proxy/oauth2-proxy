package providers

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"net/url"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	internaloidc "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/oidc"
)

const (
	accessTokenHeader    = "ewogICJhbGciOiAiUlMyNTYiLAogICJ0eXAiOiAiSldUIgp9"
	accessTokenSignature = "dyt0CoTl4WoVjAHI9Q_CwSKhl6d_9rhM3NrXuJttkao"
	defaultAudienceClaim = "aud"
	mockClientID         = "cd6d4fae-f6a6-4a34-8454-2c6b598e9532"
)

var accessTokenPayload = base64.StdEncoding.EncodeToString([]byte(
	fmt.Sprintf(`{"%s": "%s", "realm_access": {"roles": ["write"]}, "resource_access": {"default": {"roles": ["read"]}}}`, defaultAudienceClaim, mockClientID)))

type DummyKeySet struct{}

func (DummyKeySet) VerifySignature(_ context.Context, _ string) (payload []byte, err error) {
	p, _ := base64.RawURLEncoding.DecodeString(accessTokenPayload)
	return p, nil
}

func getAccessToken() string {
	return fmt.Sprintf("%s.%s.%s", accessTokenHeader, accessTokenPayload, accessTokenSignature)
}

func newTestKeycloakOIDCSetup() (*httptest.Server, *KeycloakOIDCProvider) {
	redeemURL, server := newOIDCServer([]byte(fmt.Sprintf(`{"email": "new@thing.com", "expires_in": 300, "access_token": "%v"}`, getAccessToken())))
	provider := newKeycloakOIDCProvider(redeemURL, options.Provider{})
	return server, provider
}

func newKeycloakOIDCProvider(serverURL *url.URL, opts options.Provider) *KeycloakOIDCProvider {
	verificationOptions := internaloidc.IDTokenVerificationOptions{
		AudienceClaims: []string{defaultAudienceClaim},
		ClientID:       mockClientID,
	}
	p := NewKeycloakOIDCProvider(
		&ProviderData{
			LoginURL: &url.URL{
				Scheme: "https",
				Host:   "keycloak-oidc.com",
				Path:   "/oauth/auth"},
			RedeemURL: &url.URL{
				Scheme: "https",
				Host:   "keycloak-oidc.com",
				Path:   "/oauth/token"},
			ProfileURL: &url.URL{
				Scheme: "https",
				Host:   "keycloak-oidc.com",
				Path:   "/api/v3/user"},
			ValidateURL: &url.URL{
				Scheme: "https",
				Host:   "keycloak-oidc.com",
				Path:   "/api/v3/user"},
		},
		opts)

	if serverURL != nil {
		p.RedeemURL.Scheme = serverURL.Scheme
		p.RedeemURL.Host = serverURL.Host
	}

	keyset := DummyKeySet{}
	p.Verifier = internaloidc.NewVerifier(oidc.NewVerifier("", keyset, &oidc.Config{
		ClientID:          "client",
		SkipIssuerCheck:   true,
		SkipClientIDCheck: true,
		SkipExpiryCheck:   true,
	}), verificationOptions)
	p.EmailClaim = "email"
	p.GroupsClaim = "groups"
	return p
}

var _ = Describe("Keycloak OIDC Provider Tests", func() {
	Context("New Provider Init", func() {
		It("creates new keycloak oidc provider with expected defaults", func() {
			p := newKeycloakOIDCProvider(nil, options.Provider{})
			providerData := p.Data()
			Expect(providerData.ProviderName).To(Equal(keycloakOIDCProviderName))
			Expect(providerData.LoginURL.String()).To(Equal("https://keycloak-oidc.com/oauth/auth"))
			Expect(providerData.RedeemURL.String()).To(Equal("https://keycloak-oidc.com/oauth/token"))
			Expect(providerData.ProfileURL.String()).To(Equal("https://keycloak-oidc.com/api/v3/user"))
			Expect(providerData.ValidateURL.String()).To(Equal("https://keycloak-oidc.com/api/v3/user"))
			Expect(providerData.Scope).To(Equal(oidcDefaultScope))
		})
		It("creates new keycloak oidc provider with custom scope", func() {
			p := NewKeycloakOIDCProvider(&ProviderData{Scope: "openid email"}, options.Provider{})
			providerData := p.Data()

			Expect(providerData.ProviderName).To(Equal(keycloakOIDCProviderName))
			Expect(providerData.Scope).To(Equal("openid email"))
			Expect(providerData.Scope).NotTo(Equal(oidcDefaultScope))
		})
	})

	Context("Allowed Roles", func() {
		It("should prefix allowed roles and add them to groups", func() {
			p := newKeycloakOIDCProvider(nil, options.Provider{
				KeycloakConfig: options.KeycloakOptions{
					Roles: []string{"admin", "editor"},
				},
			})
			Expect(p.AllowedGroups).To(HaveKey("role:admin"))
			Expect(p.AllowedGroups).To(HaveKey("role:editor"))
		})
	})

	Context("Enrich Session", func() {
		It("should not fail when groups are not assigned", func() {
			server, provider := newTestKeycloakOIDCSetup()
			url, err := url.Parse(server.URL)
			Expect(err).To(BeNil())
			defer server.Close()

			provider.ProfileURL = url

			existingSession := &sessions.SessionState{
				User:         "already",
				Email:        "a@b.com",
				Groups:       nil,
				IDToken:      idToken,
				AccessToken:  getAccessToken(),
				RefreshToken: refreshToken,
			}
			expectedSession := &sessions.SessionState{
				User:         "already",
				Email:        "a@b.com",
				Groups:       []string{"role:write", "role:default:read"},
				IDToken:      idToken,
				AccessToken:  getAccessToken(),
				RefreshToken: refreshToken,
			}

			err = provider.EnrichSession(context.Background(), existingSession)
			Expect(err).To(BeNil())
			Expect(existingSession).To(Equal(expectedSession))
		})

		It("should add roles to existing groups", func() {
			server, provider := newTestKeycloakOIDCSetup()
			url, err := url.Parse(server.URL)
			Expect(err).To(BeNil())
			defer server.Close()

			provider.ProfileURL = url

			existingSession := &sessions.SessionState{
				User:         "already",
				Email:        "a@b.com",
				Groups:       []string{"existing", "group"},
				IDToken:      idToken,
				AccessToken:  getAccessToken(),
				RefreshToken: refreshToken,
			}
			expectedSession := &sessions.SessionState{
				User:         "already",
				Email:        "a@b.com",
				Groups:       []string{"existing", "group", "role:write", "role:default:read"},
				IDToken:      idToken,
				AccessToken:  getAccessToken(),
				RefreshToken: refreshToken,
			}

			err = provider.EnrichSession(context.Background(), existingSession)
			Expect(err).To(BeNil())
			Expect(existingSession).To(Equal(expectedSession))
		})
	})

	Context("Refresh Session", func() {
		It("should refresh session and extract roles again", func() {
			server, provider := newTestKeycloakOIDCSetup()
			url, err := url.Parse(server.URL)
			Expect(err).To(BeNil())
			defer server.Close()

			provider.ProfileURL = url

			existingSession := &sessions.SessionState{
				User:         "already",
				Email:        "a@b.com",
				Groups:       nil,
				IDToken:      idToken,
				AccessToken:  getAccessToken(),
				RefreshToken: refreshToken,
			}

			refreshed, err := provider.RefreshSession(context.Background(), existingSession)
			Expect(err).To(BeNil())
			Expect(refreshed).To(BeTrue())
			Expect(existingSession.ExpiresOn).ToNot(BeNil())
			Expect(existingSession.CreatedAt).ToNot(BeNil())
			Expect(existingSession.Groups).To(BeEquivalentTo([]string{"role:write", "role:default:read"}))
		})
	})

	Context("Create new session from token", func() {
		It("should create a session and extract roles ", func() {
			server, provider := newTestKeycloakOIDCSetup()
			url, err := url.Parse(server.URL)
			Expect(err).To(BeNil())
			defer server.Close()

			provider.ProfileURL = url

			session, err := provider.CreateSessionFromToken(context.Background(), getAccessToken())
			Expect(err).To(BeNil())
			Expect(session.ExpiresOn).ToNot(BeNil())
			Expect(session.CreatedAt).ToNot(BeNil())
			Expect(session.Groups).To(BeEquivalentTo([]string{"role:write", "role:default:read"}))
		})
	})

})
