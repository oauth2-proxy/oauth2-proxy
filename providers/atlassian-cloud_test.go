package providers

import (
	"testing"

	. "github.com/onsi/gomega"
)

func TestNewAtlassianProvider(t *testing.T) {
	g := NewWithT(t)

	// Test that defaults are set when calling for a new provider with nothing set
	providerData := NewAtlassianProvider(&ProviderData{}).Data()
	g.Expect(providerData.ProviderName).To(Equal("Atlassian"))
	g.Expect(providerData.LoginURL.String()).To(Equal("https://auth.atlassian.com/authorize"))
	g.Expect(providerData.RedeemURL.String()).To(Equal("https://auth.atlassian.com/oauth/token"))
	g.Expect(providerData.ProfileURL.String()).To(Equal(""))
	g.Expect(providerData.ValidateURL.String()).To(Equal("https://api.atlassian.com/me"))
	g.Expect(providerData.Scope).To(Equal("read:me"))
}
