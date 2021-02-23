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

	"github.com/coreos/go-oidc"

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
			GroupsClaim:       "groups",
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

type fakeAzureKeySetStub struct{}

func (fakeAzureKeySetStub) VerifySignature(_ context.Context, jwt string) (payload []byte, err error) {
	decodeString, err := base64.RawURLEncoding.DecodeString(strings.Split(jwt, ".")[1])
	if err != nil {
		return nil, err
	}
	return decodeString, nil
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

func TestAzureProviderGetGroupsEmpty(t *testing.T) {
	b := testAzureBackend(`{ "access_token": "some_access_token", "refresh_token": "some_refresh_token", "expires_on": "1136239445", "id_token": "some_id_token" }`)
	defer b.Close()
	timestamp, _ := time.Parse(time.RFC3339, "2006-01-02T22:04:05Z")
	bURL, _ := url.Parse(b.URL)
	p := testAzureProvider(bURL.Host)

	session, err := p.Redeem(context.Background(), "http://redirect/", "code1234")
	assert.Equal(t, nil, err)
	assert.NotEqual(t, session, nil)

	err = p.EnrichSession(context.Background(), session)
	assert.Equal(t, nil, err)

	groups := session.Groups

	assert.Equal(t, timestamp, session.ExpiresOn.UTC())

	assert.Equal(t, "some_id_token", session.IDToken)
	assert.Equal(t, 0, len(groups))
}

func TestAzureProviderGetGroupsFromJWT(t *testing.T) {
	/**
	This jwt id_token
	'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdWQiLCJpc3MiOiJpc3MiLCJpYXQiOjE2MDczMzI1MzksIm5iZiI6MTYwNzMzMjUzOSwiZXhwIjoxNjA3MzMyNTY1LCJhbXIiOlsibWZhIl0sImZhbWlseV9uYW1lIjoiVXNlciIsImdpdmVuX25hbWUiOiJUZXN0IiwiZ3JvdXBzIjpbInVzZXJfZ3JvdXAiXSwiaXBhZGRyIjoiMTkyLjE2OC4xNy41IiwibmFtZSI6IlRlc3QgVXNlciAoQUQpIiwib2lkIjoib2JqZWN0X2lkIiwicmgiOiJyaCIsInN1YiI6InN1YnNjcmlwdGlvbiIsInRpZCI6InRlbmFudF9pZCIsInVuaXF1ZV9uYW1lIjoidGVzdHVzZXJAb2F1dGgyLmNvbSIsInVwbiI6InRlc3R1c2VyQG9hdXRoMi5jb20iLCJ1dGkiOiJ1dGkiLCJ2ZXIiOiIxLjAifQ.XnF9lMHViBK4wyfE6_X2c2iFlZD62WLUHJFQ7iPuvMkFb0XNBS3nVuWONkqCdQ4IFyYvzJHUQ0YH_hN5Zs8ho4fuzLcfcjjqhrLKvdY5UEAWwqeYQAWnGFc1cAwyEECwf2EcjU7ZBPVKardGTOUYyENUH_-Bdd29l_RlRyUtvnGc8WVmLaqS2EKij2oC7RbanlBUHbpLoINCpgVJrrwr87XpA8OPKqzG384AgYCvPwjCoofeXBOpz0EZw49mFQ4qdWaIjoG0wDcoZq-wKmnzly0L-sTdcYJchoXvP1ha3UXg092HK9mLuGo76DlZK6SE5FkHp2X-mP6dGWQWPo65eg'

	contains
	'''
	{
	  "aud": "aud",
	  "iss": "iss",
	  "iat": 1607332539,
	  "nbf": 1607332539,
	  "exp": 1607332565,
	  "amr": [
	    "mfa"
	  ],
	  "family_name": "User",
	  "given_name": "Test",
	  "groups": [
	    "user_group"
	  ],
	  "ipaddr": "192.168.17.5",
	  "name": "Test User (AD)",
	  "oid": "object_id",
	  "rh": "rh",
	  "sub": "subscription",
	  "tid": "tenant_id",
	  "unique_name": "testuser@oauth2.com",
	  "upn": "testuser@oauth2.com",
	  "uti": "uti",
	  "ver": "1.0"
	}
	'''

	using the public key
	-----BEGIN PUBLIC KEY-----
	MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
	vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
	aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
	tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
	e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
	V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
	MwIDAQAB
	-----END PUBLIC KEY-----

	and private key
	-----BEGIN RSA PRIVATE KEY-----
	MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw
	kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr
	m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi
	NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV
	3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2
	QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs
	kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go
	amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM
	+bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9
	D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC
	0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y
	lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+
	hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp
	bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X
	+jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B
	BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC
	2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx
	QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz
	5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9
	Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0
	NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j
	8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma
	3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K
	y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB
	jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=
	-----END RSA PRIVATE KEY-----
	*/
	idToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJhdWQiLCJpc3MiOiJpc3MiLCJpYXQiOjE2MDczMzI1MzksIm5iZiI6MTYwNzMzMjUzOSwiZXhwIjoxNjA3MzMyNTY1LCJhbXIiOlsibWZhIl0sImZhbWlseV9uYW1lIjoiVXNlciIsImdpdmVuX25hbWUiOiJUZXN0IiwiZ3JvdXBzIjpbInVzZXJfZ3JvdXAiXSwiaXBhZGRyIjoiMTkyLjE2OC4xNy41IiwibmFtZSI6IlRlc3QgVXNlciAoQUQpIiwib2lkIjoib2JqZWN0X2lkIiwicmgiOiJyaCIsInN1YiI6InN1YnNjcmlwdGlvbiIsInRpZCI6InRlbmFudF9pZCIsInVuaXF1ZV9uYW1lIjoidGVzdHVzZXJAb2F1dGgyLmNvbSIsInVwbiI6InRlc3R1c2VyQG9hdXRoMi5jb20iLCJ1dGkiOiJ1dGkiLCJ2ZXIiOiIxLjAifQ.XnF9lMHViBK4wyfE6_X2c2iFlZD62WLUHJFQ7iPuvMkFb0XNBS3nVuWONkqCdQ4IFyYvzJHUQ0YH_hN5Zs8ho4fuzLcfcjjqhrLKvdY5UEAWwqeYQAWnGFc1cAwyEECwf2EcjU7ZBPVKardGTOUYyENUH_-Bdd29l_RlRyUtvnGc8WVmLaqS2EKij2oC7RbanlBUHbpLoINCpgVJrrwr87XpA8OPKqzG384AgYCvPwjCoofeXBOpz0EZw49mFQ4qdWaIjoG0wDcoZq-wKmnzly0L-sTdcYJchoXvP1ha3UXg092HK9mLuGo76DlZK6SE5FkHp2X-mP6dGWQWPo65eg"
	b := testAzureBackend(fmt.Sprintf(`{ "access_token": "some_access_token", "refresh_token": "some_refresh_token", "expires_on": "1136239445", "id_token": "%s" }`, idToken))
	defer b.Close()
	timestamp, _ := time.Parse(time.RFC3339, "2006-01-02T22:04:05Z")
	bURL, _ := url.Parse(b.URL)
	p := testAzureProvider(bURL.Host)

	session, err := p.Redeem(context.Background(), "http://redirect/", "code1234")
	assert.Equal(t, nil, err)
	assert.NotEqual(t, session, nil)

	err = p.EnrichSession(context.Background(), session)
	assert.Equal(t, nil, err)

	groups := session.Groups

	assert.Equal(t, timestamp, session.ExpiresOn.UTC())

	assert.Equal(t, idToken, session.IDToken)
	assert.Equal(t, 1, len(groups))
	assert.Equal(t, "user_group", groups[0])
}
