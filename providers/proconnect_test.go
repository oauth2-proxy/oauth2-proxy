package providers

import (
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	. "github.com/onsi/gomega"
)

func testProConnectOIDCProvider() *ProConnectOIDCProvider {
	p := NewProConnectOIDCProvider(
		&ProviderData{}, options.OIDCOptions{})
	return p
}

func TestProConnectOIDCProviderDefaults(t *testing.T) {
	g := NewWithT(t)
	providerData := testProConnectOIDCProvider().Data()
	g.Expect(providerData.ProviderName).To(Equal("ProConnect OIDC"))
	g.Expect(providerData.LoginURL.String()).To(Equal(""))
	g.Expect(providerData.RedeemURL.String()).To(Equal(""))
	g.Expect(providerData.ProfileURL.String()).To(Equal(""))
	g.Expect(providerData.ValidateURL.String()).To(Equal(""))
	g.Expect(providerData.Scope).To(Equal("openid email profile"))
}

// todo: add test that check EnrichSession
