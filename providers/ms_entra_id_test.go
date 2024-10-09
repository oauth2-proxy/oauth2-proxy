package providers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/stretchr/testify/assert"

	. "github.com/onsi/gomega"
)

func TestAzureEntraOIDCProviderNewMultiTenant(t *testing.T) {
	g := NewWithT(t)

	provider := NewMicrosoftEntraIDProvider(&ProviderData{},
		options.Provider{OIDCConfig: options.OIDCOptions{
			IssuerURL:                      "https://login.microsoftonline.com/common/v2.0",
			InsecureSkipIssuerVerification: true,
		}},
	)
	g.Expect(provider.Data().ProviderName).To(Equal("Microsoft Entra ID"))
}

func TestAzureEntraOIDCProviderNewSingleTenant(t *testing.T) {
	g := NewWithT(t)

	provider := NewMicrosoftEntraIDProvider(&ProviderData{},
		options.Provider{OIDCConfig: options.OIDCOptions{
			IssuerURL: "https://login.microsoftonline.com/18014347-dd57-41a1-8191-7a1f734ea457/v2.0",
		}},
	)
	g.Expect(provider.Data().ProviderName).To(Equal("Microsoft Entra ID"))
}

func mockGraphAPI(noGroupMemberPermissions bool) *httptest.Server {
	groupsPath := "/v1.0/me/transitiveMemberOf"

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if noGroupMemberPermissions {
				w.WriteHeader(401)
			} else if r.URL.Path == groupsPath && r.Method == http.MethodGet {
				w.Write([]byte(`{
					"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#directoryObjects(id)",
					"value": [
						{
							"@odata.type": "#microsoft.graph.group",
							"id": "85d7d600-7804-4d92-8d43-9c33c21c130c"
						  },
						  {
							"@odata.type": "#microsoft.graph.group",
							"id": "916f0604-8a3b-4a69-bda9-06db11a8f0cd"
						  }
					]
				}`))
			}
		},
	))
}

type claimsWithGroupOverage struct {
	jwt.RegisteredClaims
	ClaimNames interface{} `json:"_claim_names,omitempty"`
}

func (c *claimsWithGroupOverage) Valid() error {
	return nil
}

func TestAzureEntraOIDCProviderEnrichSessionGroupOverage(t *testing.T) {

	// Create ID Token that indicates group overage with _claim_names
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	claimsWithGroupOverage := &claimsWithGroupOverage{
		jwt.RegisteredClaims{
			Issuer: "https://login.microsoftonline.com/18014347-dd57-41a1-8191-7a1f734ea457/v2.0",
		},
		map[string]string{"groups": "src1"},
	}

	jwtWithClaims := jwt.NewWithClaims(jwt.SigningMethodRS256, claimsWithGroupOverage)
	signedJWT, err := jwtWithClaims.SignedString(key)

	assert.NoError(t, err)

	session := CreateAuthorizedSession()
	session.IDToken = signedJWT

	// Create provider
	provider := NewMicrosoftEntraIDProvider(&ProviderData{},
		options.Provider{OIDCConfig: options.OIDCOptions{
			IssuerURL: "https://login.microsoftonline.com/18014347-dd57-41a1-8191-7a1f734ea457/v2.0",
		}},
	)

	// Create mocked Azure Graph server and override Graph URL
	mockedGraph := mockGraphAPI(false)
	mockedGraphURL, _ := url.Parse(mockedGraph.URL)
	updateURL(provider.microsoftGraphURL, mockedGraphURL.Host)

	// Test EnrichSession
	err = provider.EnrichSession(context.Background(), session)

	assert.NoError(t, err)
	assert.Contains(t, session.Groups, "85d7d600-7804-4d92-8d43-9c33c21c130c")
	assert.Contains(t, session.Groups, "916f0604-8a3b-4a69-bda9-06db11a8f0cd")

}

type mockedVerifier struct {
}

func (v *mockedVerifier) Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	return nil, nil
}

func TestAzureEntraOIDCProviderValidateSessionAllowedTenants(t *testing.T) {
	// Create multi-tenant Azure Entra provider with allowed tenants
	provider := NewMicrosoftEntraIDProvider(
		&ProviderData{
			Verifier: &mockedVerifier{},
		},
		options.Provider{
			OIDCConfig: options.OIDCOptions{
				IssuerURL:                      "https://login.microsoftonline.com/common/v2.0",
				InsecureSkipIssuerVerification: true,
				InsecureSkipNonce:              true,
			},
			MicrosoftEntraIDConfig: options.MicrosoftEntraIDOptions{
				AllowedMultiTenants: []string{"85d7d600-7804-4d92-8d43-9c33c21c130c"},
			},
		},
	)

	// Check for invalid tenant
	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Issuer: "https://login.microsoftonline.com/invalid_tenant/v2.0",
	})
	invalidJWT, err := idToken.SignedString(key)
	assert.NoError(t, err)

	session := CreateAuthorizedSession()
	session.IDToken = invalidJWT

	valid := provider.ValidateSession(context.Background(), session)
	assert.False(t, valid)

	// Check for valid tenant
	idToken = jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
		Issuer: "https://login.microsoftonline.com/85d7d600-7804-4d92-8d43-9c33c21c130c/v2.0",
	})
	validJWT, err := idToken.SignedString(key)
	assert.NoError(t, err)

	session = CreateAuthorizedSession()
	session.IDToken = validJWT

	valid = provider.ValidateSession(context.Background(), session)
	assert.True(t, valid)

}
