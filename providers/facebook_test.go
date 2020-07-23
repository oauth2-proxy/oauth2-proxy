package providers

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestNewFacebookProvider(t *testing.T) {
	g := NewWithT(t)

	// Test that defaults are set when calling for a new provider with nothing set
	providerData := NewFacebookProvider(&ProviderData{}).Data()
	g.Expect(providerData.ProviderName).To(Equal("Facebook"))
	g.Expect(providerData.LoginURL.String()).To(Equal("https://www.facebook.com/v2.5/dialog/oauth"))
	g.Expect(providerData.RedeemURL.String()).To(Equal("https://graph.facebook.com/v2.5/oauth/access_token"))
	g.Expect(providerData.ProfileURL.String()).To(Equal("https://graph.facebook.com/v2.5/me"))
	g.Expect(providerData.ValidateURL.String()).To(Equal("https://graph.facebook.com/v2.5/me"))
	g.Expect(providerData.Scope).To(Equal("public_profile email"))
}
