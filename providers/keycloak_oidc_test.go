package providers

import (
	"net/url"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Keycloak OIDC Provider Tests", func() {
	Context("New Provider Init", func() {
		It("uses the passed ProviderData", func() {
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
					Scope: "openid email profile"})
			providerData := p.Data()

			Expect(providerData.ProviderName).To(Equal(keycloakOIDCProviderName))
			Expect(providerData.LoginURL.String()).To(Equal("https://keycloak-oidc.com/oauth/auth"))
			Expect(providerData.RedeemURL.String()).To(Equal("https://keycloak-oidc.com/oauth/token"))
			Expect(providerData.ProfileURL.String()).To(Equal("https://keycloak-oidc.com/api/v3/user"))
			Expect(providerData.ValidateURL.String()).To(Equal("https://keycloak-oidc.com/api/v3/user"))
			Expect(providerData.Scope).To(Equal("openid email profile"))
		})
	})
})
