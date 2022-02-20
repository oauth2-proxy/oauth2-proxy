package providers

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	. "github.com/onsi/gomega"
)

const (
	clientID     = "bazquux"
	clientSecret = "xyzzyplugh"
	providerID   = "providerID"

	msIssuerURL = "https://login.microsoftonline.com/fabrikamb2c.onmicrosoft.com/v2.0/"
	msKeysURL   = "https://login.microsoftonline.com/fabrikamb2c.onmicrosoft.com/discovery/v2.0/keys"
	msAuthURL   = "https://login.microsoftonline.com/fabrikamb2c.onmicrosoft.com/oauth2/v2.0/authorize?p=b2c_1_sign_in"
	msTokenURL  = "https://login.microsoftonline.com/fabrikamb2c.onmicrosoft.com/oauth2/v2.0/token?p=b2c_1_sign_in"
)

func TestClientSecretFileOptionFails(t *testing.T) {
	g := NewWithT(t)

	providerConfig := options.Provider{
		ID:               providerID,
		Type:             "google",
		ClientID:         clientID,
		ClientSecretFile: clientSecret,
	}

	p, err := newProviderDataFromConfig(providerConfig)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(p.ClientSecretFile).To(Equal(clientSecret))
	g.Expect(p.ClientSecret).To(BeEmpty())

	s, err := p.GetClientSecret()
	g.Expect(err).To(HaveOccurred())
	g.Expect(s).To(BeEmpty())
}

func TestClientSecretFileOption(t *testing.T) {
	g := NewWithT(t)

	f, err := ioutil.TempFile("", "client_secret_temp_file_")
	g.Expect(err).ToNot(HaveOccurred())

	clientSecretFileName := f.Name()

	defer func() {
		g.Expect(f.Close()).To(Succeed())
		g.Expect(os.Remove(clientSecretFileName)).To(Succeed())
	}()

	_, err = f.WriteString("testcase")
	g.Expect(err).ToNot(HaveOccurred())

	providerConfig := options.Provider{
		ID:               providerID,
		Type:             "google",
		ClientID:         clientID,
		ClientSecretFile: clientSecretFileName,
	}

	p, err := newProviderDataFromConfig(providerConfig)
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(p.ClientSecretFile).To(Equal(clientSecretFileName))
	g.Expect(p.ClientSecret).To(BeEmpty())

	s, err := p.GetClientSecret()
	g.Expect(err).ToNot(HaveOccurred())
	g.Expect(s).To(Equal("testcase"))
}

func TestSkipOIDCDiscovery(t *testing.T) {
	g := NewWithT(t)
	providerConfig := options.Provider{
		ID:               providerID,
		Type:             "oidc",
		ClientID:         clientID,
		ClientSecretFile: clientSecret,
		OIDCConfig: options.OIDCOptions{
			IssuerURL:     msIssuerURL,
			SkipDiscovery: true,
		},
	}

	_, err := newProviderDataFromConfig(providerConfig)
	g.Expect(err).To(MatchError("error building OIDC ProviderVerifier: invalid provider verifier options: missing required setting: jwks-url"))

	providerConfig.LoginURL = msAuthURL
	providerConfig.RedeemURL = msTokenURL
	providerConfig.OIDCConfig.JwksURL = msKeysURL

	_, err = newProviderDataFromConfig(providerConfig)
	g.Expect(err).ToNot(HaveOccurred())
}

func TestURLsCorrectlyParsed(t *testing.T) {
	g := NewWithT(t)

	providerConfig := options.Provider{
		ID:               providerID,
		Type:             "oidc",
		ClientID:         clientID,
		ClientSecretFile: clientSecret,
		LoginURL:         msAuthURL,
		RedeemURL:        msTokenURL,
		OIDCConfig: options.OIDCOptions{
			IssuerURL:     msIssuerURL,
			SkipDiscovery: true,
			JwksURL:       msKeysURL,
		},
	}

	pd, err := newProviderDataFromConfig(providerConfig)
	g.Expect(err).ToNot(HaveOccurred())

	g.Expect(pd.LoginURL.String()).To(Equal(msAuthURL))
	g.Expect(pd.RedeemURL.String()).To(Equal(msTokenURL))
}

func TestScope(t *testing.T) {
	g := NewWithT(t)

	testCases := []struct {
		name            string
		configuredScope string
		expectedScope   string
		allowedGroups   []string
	}{
		{
			name:            "with no scope provided",
			configuredScope: "",
			expectedScope:   "openid email profile",
		},
		{
			name:            "with no scope provided and groups",
			configuredScope: "",
			expectedScope:   "openid email profile groups",
			allowedGroups:   []string{"foo"},
		},
		{
			name:            "with a configured scope provided",
			configuredScope: "openid",
			expectedScope:   "openid",
		},
	}

	for _, tc := range testCases {
		providerConfig := options.Provider{
			ID:               providerID,
			Type:             "oidc",
			ClientID:         clientID,
			ClientSecretFile: clientSecret,
			LoginURL:         msAuthURL,
			RedeemURL:        msTokenURL,
			Scope:            tc.configuredScope,
			AllowedGroups:    tc.allowedGroups,
			OIDCConfig: options.OIDCOptions{
				IssuerURL:     msIssuerURL,
				SkipDiscovery: true,
				JwksURL:       msKeysURL,
			},
		}

		pd, err := newProviderDataFromConfig(providerConfig)
		g.Expect(err).ToNot(HaveOccurred())

		g.Expect(pd.Scope).To(Equal(tc.expectedScope))
	}
}
