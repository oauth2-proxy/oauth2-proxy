package providers

import (
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

	f, err := os.CreateTemp("", "client_secret_temp_file_")
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
		configuredType  options.ProviderType
		configuredScope string
		expectedScope   string
		allowedGroups   []string
	}{
		{
			name:            "oidc: with no scope provided",
			configuredType:  "oidc",
			configuredScope: "",
			expectedScope:   "openid email profile",
		},
		{
			name:            "oidc: with no scope provided and allowed groups",
			configuredType:  "oidc",
			configuredScope: "",
			expectedScope:   "openid email profile groups",
			allowedGroups:   []string{"foo"},
		},
		{
			name:            "oidc: with custom scope including groups without allowed groups",
			configuredType:  "oidc",
			configuredScope: "myscope groups",
			expectedScope:   "myscope groups",
		},
		{
			name:            "oidc: with custom scope without groups but allowed groups",
			configuredType:  "oidc",
			configuredScope: "myscope",
			expectedScope:   "myscope",
			allowedGroups:   []string{"foo"},
		},
		{
			name:            "oidc: with custom scope with groups and allowed groups",
			configuredType:  "oidc",
			configuredScope: "myscope groups",
			expectedScope:   "myscope groups",
			allowedGroups:   []string{"foo"},
		},
		{
			name:            "oidc: with a configured scope provided",
			configuredType:  "oidc",
			configuredScope: "openid",
			expectedScope:   "openid",
		},
		{
			name:            "github: with no scope provided",
			configuredType:  "github",
			configuredScope: "",
			expectedScope:   "user:email read:org",
		},
		{
			name:            "github: with a configured scope provided",
			configuredType:  "github",
			configuredScope: "read:user read:org",
			expectedScope:   "read:user read:org",
		},
		{
			name:            "keycloak: with no scope provided and groups",
			configuredType:  "keycloak-oidc",
			configuredScope: "",
			expectedScope:   "openid email profile groups",
			allowedGroups:   []string{"foo"},
		},
		{
			name:            "keycloak: with custom scope and groups",
			configuredType:  "keycloak-oidc",
			configuredScope: "myscope",
			expectedScope:   "myscope",
			allowedGroups:   []string{"foo"},
		},
		{
			name:            "keycloak: with custom scope and groups scope",
			configuredType:  "keycloak-oidc",
			configuredScope: "myscope groups",
			expectedScope:   "myscope groups",
			allowedGroups:   []string{"foo"},
		},
	}

	for _, tc := range testCases {
		providerConfig := options.Provider{
			ID:               providerID,
			Type:             tc.configuredType,
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

		pd, err := NewProvider(providerConfig)
		g.Expect(err).ToNot(HaveOccurred())

		g.Expect(pd.Data().Scope).To(Equal(tc.expectedScope))
	}
}

func TestForcedMethodS256(t *testing.T) {
	g := NewWithT(t)
	options := options.NewOptions()
	options.Providers[0].CodeChallengeMethod = CodeChallengeMethodS256
	method := parseCodeChallengeMethod(options.Providers[0])

	g.Expect(method).To(Equal(CodeChallengeMethodS256))
}

func TestForcedMethodPlain(t *testing.T) {
	g := NewWithT(t)
	options := options.NewOptions()
	options.Providers[0].CodeChallengeMethod = CodeChallengeMethodPlain
	method := parseCodeChallengeMethod(options.Providers[0])

	g.Expect(method).To(Equal(CodeChallengeMethodPlain))
}

func TestPrefersS256(t *testing.T) {
	g := NewWithT(t)
	options := options.NewOptions()
	method := parseCodeChallengeMethod(options.Providers[0])

	g.Expect(method).To(Equal(""))
}

func TestCanOverwriteS256(t *testing.T) {
	g := NewWithT(t)
	options := options.NewOptions()
	options.Providers[0].CodeChallengeMethod = "plain"
	method := parseCodeChallengeMethod(options.Providers[0])

	g.Expect(method).To(Equal(CodeChallengeMethodPlain))
}

func TestEmailClaimCorrectlySet(t *testing.T) {
	g := NewWithT(t)

	testCases := []struct {
		name               string
		userIDClaim        string
		emailClaim         string
		expectedEmailClaim string
	}{
		{
			name:               "do not override EmailClaim if UserIDClaim is empty",
			userIDClaim:        "",
			emailClaim:         "email",
			expectedEmailClaim: "email",
		},
		{
			name:               "set EmailClaim to UserIDClaim",
			userIDClaim:        "user_id_claim",
			emailClaim:         "email",
			expectedEmailClaim: "user_id_claim",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
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
					UserIDClaim:   tc.userIDClaim,
					EmailClaim:    tc.emailClaim,
				},
			}

			pd, err := newProviderDataFromConfig(providerConfig)
			g.Expect(err).ToNot(HaveOccurred())

			g.Expect(pd.EmailClaim).To(Equal(tc.expectedEmailClaim))
		})
	}
}
