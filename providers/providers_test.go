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
			IssuerURL:     "https://login.microsoftonline.com/fabrikamb2c.onmicrosoft.com/v2.0/",
			SkipDiscovery: true,
		},
	}

	_, err := newProviderDataFromConfig(providerConfig)
	g.Expect(err).To(MatchError("error setting OIDC configuration: [missing required setting: login-url, missing required setting: redeem-url, missing required setting: oidc-jwks-url]"))

	providerConfig.LoginURL = "https://login.microsoftonline.com/fabrikamb2c.onmicrosoft.com/oauth2/v2.0/authorize?p=b2c_1_sign_in"
	providerConfig.RedeemURL = "https://login.microsoftonline.com/fabrikamb2c.onmicrosoft.com/oauth2/v2.0/token?p=b2c_1_sign_in"
	providerConfig.OIDCConfig.JwksURL = "https://login.microsoftonline.com/fabrikamb2c.onmicrosoft.com/discovery/v2.0/keys"

	_, err = newProviderDataFromConfig(providerConfig)
	g.Expect(err).ToNot(HaveOccurred())
}
