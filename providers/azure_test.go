package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"

	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

type fakeAzureKeySetStub struct{}

func (fakeAzureKeySetStub) VerifySignature(_ context.Context, jwt string) (payload []byte, err error) {
	decodeString, err := base64.RawURLEncoding.DecodeString(strings.Split(jwt, ".")[1])
	if err != nil {
		return nil, err
	}
	return decodeString, nil
}

type azureOAuthPayload struct {
	AccessToken  string `json:"access_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresOn    int64  `json:"expires_on,omitempty,string"`
	IDToken      string `json:"id_token,omitempty"`
}

func testAzureProvider(hostname string) *AzureProvider {
	p := NewAzureProvider(
		&ProviderData{
			ProviderName:      "",
			LoginURL:          &url.URL{},
			RedeemURL:         &url.URL{},
			ProfileURL:        &url.URL{},
			ValidateURL:       &url.URL{},
			ProtectedResource: &url.URL{},
			Scope:             "",
			EmailClaim:        "email",
			Verifier: oidc.NewVerifier(
				"https://issuer.example.com",
				fakeAzureKeySetStub{},
				&oidc.Config{
					ClientID:          "cd6d4fae-f6a6-4a34-8454-2c6b598e9532",
					SkipClientIDCheck: true,
					SkipIssuerCheck:   true,
					SkipExpiryCheck:   true,
				},
			),
		})

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
	return testAzureBackendWithError(payload, false)
}

func testAzureBackendWithError(payload string, injectError bool) *httptest.Server {
	path := "/v1.0/me"

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if (r.URL.Path != path) && r.Method != http.MethodPost {
				w.WriteHeader(404)
			} else if r.Method == http.MethodPost && r.Body != nil {
				if injectError {
					w.WriteHeader(400)
				} else {
					w.WriteHeader(200)
				}
				w.Write([]byte(payload))
			} else if !IsAuthorizedInHeader(r.Header) {
				w.WriteHeader(403)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			}
		}))
}

func TestAzureProviderEnrichSession(t *testing.T) {
	testCases := []struct {
		Description             string
		Email                   string
		PayloadFromAzureBackend string
		ExpectedEmail           string
		ExpectedError           error
	}{
		{
			Description:             "should return email using mail property from Azure backend",
			PayloadFromAzureBackend: `{ "mail": "user@windows.net" }`,
			ExpectedEmail:           "user@windows.net",
		},
		{
			Description:             "should return email using otherMails property returned from Azure backend",
			PayloadFromAzureBackend: `{ "mail": null, "otherMails": ["user@windows.net", "altuser@windows.net"] }`,
			ExpectedEmail:           "user@windows.net",
		},
		{
			Description:             "should return email using userPrincipalName from Azure backend",
			PayloadFromAzureBackend: `{ "mail": null, "otherMails": [], "userPrincipalName": "user@windows.net" }`,
			ExpectedEmail:           "user@windows.net",
		},
		{
			Description:             "should return error when Azure backend doesn't return email information",
			PayloadFromAzureBackend: `{ "mail": null, "otherMails": [], "userPrincipalName": null }`,
			ExpectedError:           fmt.Errorf("unable to get email address: %v", errors.New("type assertion to string failed")),
		},
		{
			Description:             "should return specific error when unable to get email",
			PayloadFromAzureBackend: `{ "mail": null, "otherMails": [], "userPrincipalName": "" }`,
			ExpectedError:           errors.New("unable to get email address"),
		},
		{
			Description:             "should return error when otherMails from Azure backend is not a valid type",
			PayloadFromAzureBackend: `{ "mail": null, "otherMails": "", "userPrincipalName": null }`,
			ExpectedError:           fmt.Errorf("unable to get email address: %v", errors.New("type assertion to string failed")),
		},
		{
			Description:   "should not query profile api when email is already set in session",
			Email:         "user@windows.net",
			ExpectedEmail: "user@windows.net",
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
			session.Email = testCase.Email
			err := p.EnrichSession(context.Background(), session)
			assert.Equal(t, testCase.ExpectedError, err)
			assert.Equal(t, testCase.ExpectedEmail, session.Email)
		})
	}
}

func TestAzureProviderRedeem(t *testing.T) {
	testCases := []struct {
		Name                 string
		RefreshToken         string
		ExpiresOn            time.Time
		EmailFromIDToken     string
		EmailFromAccessToken string
		IsIDTokenMalformed   bool
		InjectRedeemURLError bool
	}{
		{
			Name:             "with id_token returned",
			EmailFromIDToken: "foo1@example.com",
			RefreshToken:     "some_refresh_token",
			ExpiresOn:        time.Now().Add(time.Hour),
		},
		{
			Name:                 "without id_token returned, fallback to access token",
			EmailFromAccessToken: "foo2@example.com",
			RefreshToken:         "some_refresh_token",
			ExpiresOn:            time.Now().Add(time.Hour),
		},
		{
			Name:                 "id_token malformed, fallback to access token",
			EmailFromAccessToken: "foo3@example.com",
			RefreshToken:         "some_refresh_token",
			ExpiresOn:            time.Now().Add(time.Hour),
			IsIDTokenMalformed:   true,
		},
		{
			Name:                 "both id_token and access tokens are valid, return email from id_token",
			EmailFromIDToken:     "foo1@example.com",
			EmailFromAccessToken: "foo3@example.com",
			RefreshToken:         "some_refresh_token",
			ExpiresOn:            time.Now().Add(time.Hour),
		},
		{
			Name:                 "redeem URL failed, should return error",
			EmailFromIDToken:     "foo1@example.com",
			EmailFromAccessToken: "foo3@example.com",
			RefreshToken:         "some_refresh_token",
			ExpiresOn:            time.Now().Add(time.Hour),
			InjectRedeemURLError: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			idTokenString := ""
			accessTokenString := ""
			if testCase.EmailFromIDToken != "" {
				var err error
				token := idTokenClaims{Email: testCase.EmailFromIDToken}
				idTokenString, err = newSignedTestIDToken(token)
				assert.NoError(t, err)
			}
			if testCase.EmailFromAccessToken != "" {
				var err error
				token := idTokenClaims{Email: testCase.EmailFromAccessToken}
				accessTokenString, err = newSignedTestIDToken(token)
				assert.NoError(t, err)
			}
			if testCase.IsIDTokenMalformed {
				idTokenString = "this is a malformed id_token"
			}
			payload := azureOAuthPayload{
				IDToken:      idTokenString,
				RefreshToken: testCase.RefreshToken,
				AccessToken:  accessTokenString,
				ExpiresOn:    testCase.ExpiresOn.Unix(),
			}

			payloadBytes, err := json.Marshal(payload)
			assert.NoError(t, err)

			b := testAzureBackendWithError(string(payloadBytes), testCase.InjectRedeemURLError)
			defer b.Close()

			bURL, _ := url.Parse(b.URL)
			p := testAzureProvider(bURL.Host)
			p.Data().RedeemURL.Path = "/common/oauth2/token"
			s, err := p.Redeem(context.Background(), "https://localhost", "1234")
			if testCase.InjectRedeemURLError {
				assert.NotNil(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, idTokenString, s.IDToken)
				assert.Equal(t, accessTokenString, s.AccessToken)
				assert.Equal(t, testCase.ExpiresOn.Unix(), s.ExpiresOn.Unix())
				assert.Equal(t, testCase.RefreshToken, s.RefreshToken)
				if testCase.EmailFromIDToken != "" {
					assert.Equal(t, testCase.EmailFromIDToken, s.Email)
				} else {
					assert.Equal(t, testCase.EmailFromAccessToken, s.Email)
				}
			}
		})
	}
}

func TestAzureProviderProtectedResourceConfigured(t *testing.T) {
	p := testAzureProvider("")
	p.ProtectedResource, _ = url.Parse("http://my.resource.test")
	result := p.GetLoginURL("https://my.test.app/oauth", "")
	assert.Contains(t, result, "resource="+url.QueryEscape("http://my.resource.test"))
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
	email := "foo@example.com"
	idToken := idTokenClaims{Email: email}
	idTokenString, err := newSignedTestIDToken(idToken)
	assert.NoError(t, err)
	timestamp, err := time.Parse(time.RFC3339, "3006-01-02T22:04:05Z")
	assert.NoError(t, err)
	payload := azureOAuthPayload{
		IDToken:      idTokenString,
		RefreshToken: "new_some_refresh_token",
		AccessToken:  "new_some_access_token",
		ExpiresOn:    timestamp.Unix(),
	}

	payloadBytes, err := json.Marshal(payload)
	assert.NoError(t, err)
	b := testAzureBackend(string(payloadBytes))
	defer b.Close()
	bURL, _ := url.Parse(b.URL)
	p := testAzureProvider(bURL.Host)

	expires := time.Now().Add(time.Duration(-1) * time.Hour)
	session := &sessions.SessionState{AccessToken: "some_access_token", RefreshToken: "some_refresh_token", IDToken: "some_id_token", ExpiresOn: &expires}
	refreshNeeded, err := p.RefreshSessionIfNeeded(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.True(t, refreshNeeded)
	assert.NotEqual(t, session, nil)
	assert.Equal(t, "new_some_access_token", session.AccessToken)
	assert.Equal(t, "new_some_refresh_token", session.RefreshToken)
	assert.Equal(t, idTokenString, session.IDToken)
	assert.Equal(t, email, session.Email)
	assert.Equal(t, timestamp, session.ExpiresOn.UTC())
}
