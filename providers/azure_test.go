package providers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"

	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

func testAzureProvider(hostname string) *AzureProvider {
	p := NewAzureProvider(
		&ProviderData{
			ProviderName:      "",
			LoginURL:          &url.URL{},
			RedeemURL:         &url.URL{},
			ProfileURL:        &url.URL{},
			ValidateURL:       &url.URL{},
			ProtectedResource: &url.URL{},
			Scope:             ""})

	if hostname != "" {
		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		updateURL(p.Data().ProfileURL, hostname)
		updateURL(p.Data().ValidateURL, hostname)
		updateURL(p.Data().ProtectedResource, hostname)
	}
	return p
}

func TestNewAzureProvider(t *testing.T) {
	g := NewWithT(t)

	// Test that defaults are set when calling for a new provider with nothing set
	providerData := NewAzureProvider(&ProviderData{}).Data()
	g.Expect(providerData.ProviderName).To(Equal("Azure"))
	g.Expect(providerData.LoginURL.String()).To(Equal("https://login.microsoftonline.com/common/oauth2/authorize"))
	g.Expect(providerData.RedeemURL.String()).To(Equal("https://login.microsoftonline.com/common/oauth2/token"))
	g.Expect(providerData.ProfileURL.String()).To(Equal("https://graph.microsoft.com/v1.0/me"))
	g.Expect(providerData.ValidateURL.String()).To(Equal("https://graph.microsoft.com/v1.0/me"))
	g.Expect(providerData.Scope).To(Equal("openid"))
}

func TestAzureProviderOverrides(t *testing.T) {
	p := NewAzureProvider(
		&ProviderData{
			LoginURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/auth"},
			RedeemURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/token"},
			ProfileURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/profile"},
			ValidateURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/tokeninfo"},
			ProtectedResource: &url.URL{
				Scheme: "https",
				Host:   "example.com"},
			Scope: "profile"})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Azure", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/oauth/auth",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://example.com/oauth/profile",
		p.Data().ProfileURL.String())
	assert.Equal(t, "https://example.com/oauth/tokeninfo",
		p.Data().ValidateURL.String())
	assert.Equal(t, "https://example.com",
		p.Data().ProtectedResource.String())
	assert.Equal(t, "profile", p.Data().Scope)
}

func TestAzureSetTenant(t *testing.T) {
	p := testAzureProvider("")
	p.Configure("example")
	assert.Equal(t, "Azure", p.Data().ProviderName)
	assert.Equal(t, "example", p.Tenant)
	assert.Equal(t, "https://login.microsoftonline.com/example/oauth2/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://login.microsoftonline.com/example/oauth2/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://graph.microsoft.com/v1.0/me",
		p.Data().ProfileURL.String())
	assert.Equal(t, "https://graph.microsoft.com",
		p.Data().ProtectedResource.String())
	assert.Equal(t, "https://graph.microsoft.com/v1.0/me", p.Data().ValidateURL.String())
	assert.Equal(t, "openid", p.Data().Scope)
}

func testAzureBackend(payload string) *httptest.Server {
	path := "/v1.0/me"

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if (r.URL.Path != path) && r.Method != http.MethodPost {
				w.WriteHeader(404)
			} else if r.Method == http.MethodPost && r.Body != nil {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			} else if !IsAuthorizedInHeader(r.Header) {
				w.WriteHeader(403)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			}
		}))
}

func TestAzureProviderEnrichSessionState(t *testing.T) {
	testCases := []struct {
		Description             string
		IDToken                 string
		PayloadFromAzureBackend string
		ExpectedEmail           string
		ExpectedError           error
	}{
		{
			Description:             "EnrichSessionState should return email using mail property from Azure backend",
			PayloadFromAzureBackend: `{ "mail": "user@windows.net" }`,
			ExpectedEmail:           "user@windows.net",
			ExpectedError:           nil,
		},
		{
			Description:             "EnrichSessionState should return email using otherMails property returned from Azure backend",
			PayloadFromAzureBackend: `{ "mail": null, "otherMails": ["user@windows.net", "altuser@windows.net"] }`,
			ExpectedEmail:           "user@windows.net",
			ExpectedError:           nil,
		},
		{
			Description:             "EnrichSessionState should return email using userPrincipalName from Azure backend",
			PayloadFromAzureBackend: `{ "mail": null, "otherMails": [], "userPrincipalName": "user@windows.net" }`,
			ExpectedEmail:           "user@windows.net",
			ExpectedError:           nil,
		},
		{
			Description:             "EnrichSessionState should return error when Azure backend doesn't return email information",
			PayloadFromAzureBackend: `{ "mail": null, "otherMails": [], "userPrincipalName": null }`,
			ExpectedEmail:           "",
			ExpectedError:           errors.New("type assertion to string failed"),
		},
		{
			Description:             "EnrichSessionState should return empty email when userPrincipalName from Azure backend is empty",
			PayloadFromAzureBackend: `{ "mail": null, "otherMails": [], "userPrincipalName": "" }`,
			ExpectedEmail:           "",
			ExpectedError:           nil,
		},
		{
			Description:             "EnrichSessionState should return error when otherMails from Azure backend is not a valid type",
			PayloadFromAzureBackend: `{ "mail": null, "otherMails": "", "userPrincipalName": null }`,
			ExpectedEmail:           "",
			ExpectedError:           errors.New("type assertion to string failed"),
		},
		{
			Description: "EnrichSessionState should return email from id_token",
			// { "sub": "1234567890", "email": "foo@bar.com", "iat": 1516239022 }
			IDToken:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZW1haWwiOiJmb29AYmFyLmNvbSIsImlhdCI6MTUxNjIzOTAyMn0.XRuL4Y2VPSToNB8vMvmlB-X3BwahUJzUXNx6vmzODjk",
			ExpectedEmail: "foo@bar.com",
			ExpectedError: nil,
		},
		{
			Description:             "EnrichSessionState should return email from Azure backend when id_token doesn't email claim",
			PayloadFromAzureBackend: `{ "mail": "user@windows.net", "otherMails": [], "userPrincipalName": "" }`,
			// { "sub": "1234567890", "iat": 1516239022 }
			IDToken:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ.L8i6g3PfcHlioHCCPURC9pmXT7gdJpx3kOoyAfNUwCc",
			ExpectedEmail: "user@windows.net",
			ExpectedError: nil,
		},
		{
			Description:             "EnrichSessionState should return email from Azure backend when id_token is invalid",
			PayloadFromAzureBackend: `{ "mail": "user@windows.net", "otherMails": [], "userPrincipalName": "" }`,
			// this is not a valid id_token
			IDToken:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwia.L8i6g3PfcHlioHCCPURC9pmXT7gdJpx3kOoyAfNUwCc",
			ExpectedEmail: "user@windows.net",
			ExpectedError: nil,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Description, func(t *testing.T) {
			var (
				b    *httptest.Server
				host string
			)
			if testCase.PayloadFromAzureBackend != "" {
				b = testAzureBackend(testCase.PayloadFromAzureBackend)
				defer b.Close()

				bURL, _ := url.Parse(b.URL)
				host = bURL.Host
			}
			p := testAzureProvider(host)
			session := CreateAuthorizedSession()
			session.IDToken = testCase.IDToken
			err := p.EnrichSessionState(context.Background(), session)
			assert.Equal(t, testCase.ExpectedError, err)
			assert.Equal(t, testCase.ExpectedEmail, session.Email)
		})
	}
}

func TestAzureProviderRedeemReturnsIdToken(t *testing.T) {
	b := testAzureBackend(`{ "id_token": "testtoken1234", "expires_on": "1136239445", "refresh_token": "refresh1234" }`)
	defer b.Close()
	timestamp, err := time.Parse(time.RFC3339, "2006-01-02T22:04:05Z")
	assert.Equal(t, nil, err)

	bURL, _ := url.Parse(b.URL)
	p := testAzureProvider(bURL.Host)
	p.Data().RedeemURL.Path = "/common/oauth2/token"
	s, err := p.Redeem(context.Background(), "https://localhost", "1234")
	assert.Equal(t, nil, err)
	assert.Equal(t, "testtoken1234", s.IDToken)
	assert.Equal(t, timestamp, s.ExpiresOn.UTC())
	assert.Equal(t, "refresh1234", s.RefreshToken)
}

func TestAzureProviderProtectedResourceConfigured(t *testing.T) {
	p := testAzureProvider("")
	p.ProtectedResource, _ = url.Parse("http://my.resource.test")
	result := p.GetLoginURL("https://my.test.app/oauth", "")
	assert.Contains(t, result, "resource="+url.QueryEscape("http://my.resource.test"))
}

func TestAzureProviderGetsTokensInRedeem(t *testing.T) {
	b := testAzureBackend(`{ "access_token": "some_access_token", "refresh_token": "some_refresh_token", "expires_on": "1136239445", "id_token": "some_id_token" }`)
	defer b.Close()
	timestamp, _ := time.Parse(time.RFC3339, "2006-01-02T22:04:05Z")
	bURL, _ := url.Parse(b.URL)
	p := testAzureProvider(bURL.Host)

	session, err := p.Redeem(context.Background(), "http://redirect/", "code1234")
	assert.Equal(t, nil, err)
	assert.NotEqual(t, session, nil)
	assert.Equal(t, "some_access_token", session.AccessToken)
	assert.Equal(t, "some_refresh_token", session.RefreshToken)
	assert.Equal(t, "some_id_token", session.IDToken)
	assert.Equal(t, timestamp, session.ExpiresOn.UTC())
}

func TestAzureProviderNotRefreshWhenNotExpired(t *testing.T) {
	p := testAzureProvider("")

	expires := time.Now().Add(time.Duration(1) * time.Hour)
	session := &sessions.SessionState{AccessToken: "some_access_token", RefreshToken: "some_refresh_token", IDToken: "some_id_token", ExpiresOn: &expires}
	refreshNeeded, err := p.RefreshSessionIfNeeded(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.False(t, refreshNeeded)
}

func TestAzureProviderRefreshWhenExpired(t *testing.T) {
	b := testAzureBackend(`{ "access_token": "new_some_access_token", "refresh_token": "new_some_refresh_token", "expires_on": "32693148245", "id_token": "new_some_id_token" }`)
	defer b.Close()
	timestamp, _ := time.Parse(time.RFC3339, "3006-01-02T22:04:05Z")
	bURL, _ := url.Parse(b.URL)
	p := testAzureProvider(bURL.Host)

	expires := time.Now().Add(time.Duration(-1) * time.Hour)
	session := &sessions.SessionState{AccessToken: "some_access_token", RefreshToken: "some_refresh_token", IDToken: "some_id_token", ExpiresOn: &expires}
	_, err := p.RefreshSessionIfNeeded(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.NotEqual(t, session, nil)
	assert.Equal(t, "new_some_access_token", session.AccessToken)
	assert.Equal(t, "new_some_refresh_token", session.RefreshToken)
	assert.Equal(t, "new_some_id_token", session.IDToken)
	assert.Equal(t, timestamp, session.ExpiresOn.UTC())
}
