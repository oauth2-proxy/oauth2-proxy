package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

const testClientAssertion = "eyJhbGciOiJSUzI1NiJ9.dGVzdA.c2ln"

func writeTestAssertionFile(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))

	return path
}

func newAssertionOIDCSetup(t *testing.T, assertionFile string, body []byte) (*httptest.Server, *OIDCProvider, *capturedTokenRequest) {
	t.Helper()

	captured := &capturedTokenRequest{}
	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		captured.form = r.PostForm
		captured.authorization = r.Header.Get("Authorization")

		rw.Header().Add("content-type", "application/json")
		_, _ = rw.Write(body)
	}))

	u, err := url.Parse(s.URL)
	require.NoError(t, err)

	provider := newOIDCProvider(u, false)
	provider.ClientSecret = ""
	provider.ClientAssertionFile = assertionFile

	return s, provider, captured
}

type capturedTokenRequest struct {
	form          url.Values
	authorization string
}

func TestUsesClientAssertion(t *testing.T) {
	assert.False(t, (&ProviderData{}).UsesClientAssertion())
	assert.True(t, (&ProviderData{ClientAssertionFile: "/token"}).UsesClientAssertion())
}

func TestGetClientAssertion(t *testing.T) {
	t.Run("reads the assertion and strips surrounding whitespace", func(t *testing.T) {
		p := &ProviderData{ClientAssertionFile: writeTestAssertionFile(t, testClientAssertion+"\n")}

		assertion, err := p.GetClientAssertion()
		assert.NoError(t, err)
		assert.Equal(t, testClientAssertion, assertion)
	})

	t.Run("rereads the file so rotated assertions are picked up", func(t *testing.T) {
		path := writeTestAssertionFile(t, "first")
		p := &ProviderData{ClientAssertionFile: path}

		assertion, err := p.GetClientAssertion()
		assert.NoError(t, err)
		assert.Equal(t, "first", assertion)

		require.NoError(t, os.WriteFile(path, []byte("second"), 0600))

		assertion, err = p.GetClientAssertion()
		assert.NoError(t, err)
		assert.Equal(t, "second", assertion)
	})

	t.Run("errors without leaking the path when the file is missing", func(t *testing.T) {
		p := &ProviderData{ClientAssertionFile: "/does/not/exist"}

		assertion, err := p.GetClientAssertion()
		assert.Error(t, err)
		assert.Equal(t, "could not read client assertion file", err.Error())
		assert.Empty(t, assertion)
	})
}

func TestTokenEndpointConfig(t *testing.T) {
	redeemURL, err := url.Parse("https://example.com/token")
	require.NoError(t, err)

	t.Run("uses the client secret by default", func(t *testing.T) {
		p := &ProviderData{ClientID: "client", ClientSecret: "secret", RedeemURL: redeemURL}

		c, err := p.tokenEndpointConfig("https://example.com/callback")
		assert.NoError(t, err)
		assert.Equal(t, "secret", c.ClientSecret)
		assert.Equal(t, oauth2.AuthStyleAutoDetect, c.Endpoint.AuthStyle)
		assert.Equal(t, "https://example.com/callback", c.RedirectURL)
	})

	t.Run("sends no secret and pins the auth style when using an assertion", func(t *testing.T) {
		p := &ProviderData{ClientID: "client", ClientAssertionFile: "/token", RedeemURL: redeemURL}

		c, err := p.tokenEndpointConfig("")
		assert.NoError(t, err)
		assert.Empty(t, c.ClientSecret)
		// Otherwise oauth2 probes the endpoint with an empty Basic credential
		assert.Equal(t, oauth2.AuthStyleInParams, c.Endpoint.AuthStyle)
	})
}

func TestOIDCProviderRedeemWithClientAssertion(t *testing.T) {
	idToken, err := newSignedTestIDToken(defaultIDToken)
	require.NoError(t, err)

	body, err := json.Marshal(redeemTokenResponse{
		AccessToken:  accessToken,
		ExpiresIn:    10,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		IDToken:      idToken,
	})
	require.NoError(t, err)

	assertionFile := writeTestAssertionFile(t, testClientAssertion)
	server, provider, captured := newAssertionOIDCSetup(t, assertionFile, body)
	defer server.Close()

	session, err := provider.Redeem(context.Background(), "https://example.com/callback", "code1234", "verifier")
	assert.NoError(t, err)
	assert.Equal(t, accessToken, session.AccessToken)
	assert.Equal(t, idToken, session.IDToken)
	assert.Equal(t, defaultIDToken.Email, session.Email)

	assert.Equal(t, testClientAssertion, captured.form.Get("client_assertion"))
	assert.Equal(t, clientAssertionTypeJWTBearer, captured.form.Get("client_assertion_type"))
	assert.Equal(t, "authorization_code", captured.form.Get("grant_type"))
	assert.Equal(t, "code1234", captured.form.Get("code"))
	assert.Equal(t, "verifier", captured.form.Get("code_verifier"))
	assert.Equal(t, oidcClientID, captured.form.Get("client_id"))

	assert.Empty(t, captured.form.Get("client_secret"))
	assert.Empty(t, captured.authorization)
}

func TestOIDCProviderRefreshSessionWithClientAssertion(t *testing.T) {
	idToken, err := newSignedTestIDToken(defaultIDToken)
	require.NoError(t, err)

	body, err := json.Marshal(redeemTokenResponse{
		AccessToken:  accessToken,
		ExpiresIn:    3600,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		IDToken:      idToken,
	})
	require.NoError(t, err)

	assertionFile := writeTestAssertionFile(t, testClientAssertion)
	server, provider, captured := newAssertionOIDCSetup(t, assertionFile, body)
	defer server.Close()

	session := &sessions.SessionState{
		AccessToken:  "changeit",
		IDToken:      "changeit",
		RefreshToken: "oldrefresh",
		Email:        "changeit",
		User:         "changeit",
	}

	refreshed, err := provider.RefreshSession(context.Background(), session)
	assert.NoError(t, err)
	assert.True(t, refreshed)
	assert.Equal(t, accessToken, session.AccessToken)
	assert.Equal(t, idToken, session.IDToken)
	assert.Equal(t, refreshToken, session.RefreshToken)
	assert.Equal(t, defaultIDToken.Email, session.Email)

	assert.Equal(t, testClientAssertion, captured.form.Get("client_assertion"))
	assert.Equal(t, clientAssertionTypeJWTBearer, captured.form.Get("client_assertion_type"))
	assert.Equal(t, "refresh_token", captured.form.Get("grant_type"))
	assert.Equal(t, "oldrefresh", captured.form.Get("refresh_token"))
	assert.Equal(t, oidcClientID, captured.form.Get("client_id"))
	assert.Empty(t, captured.form.Get("client_secret"))
	assert.Empty(t, captured.authorization)

	require.NotNil(t, session.ExpiresOn)
	assert.WithinDuration(t, time.Now().Add(time.Hour), *session.ExpiresOn, time.Minute)
}

func TestOIDCProviderRefreshSessionWithClientAssertionWithoutIDToken(t *testing.T) {
	body, err := json.Marshal(redeemTokenResponse{
		AccessToken:  accessToken,
		ExpiresIn:    3600,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
	})
	require.NoError(t, err)

	assertionFile := writeTestAssertionFile(t, testClientAssertion)
	server, provider, captured := newAssertionOIDCSetup(t, assertionFile, body)
	defer server.Close()

	session := &sessions.SessionState{
		AccessToken:       "oldaccess",
		IDToken:           "oldidtoken",
		RefreshToken:      "oldrefresh",
		Email:             "old@example.com",
		User:              "olduser",
		Groups:            []string{"oldgroup"},
		PreferredUsername: "oldpreferred",
	}

	refreshed, err := provider.RefreshSession(context.Background(), session)
	assert.NoError(t, err)
	assert.True(t, refreshed)

	assert.Equal(t, accessToken, session.AccessToken)
	assert.Equal(t, refreshToken, session.RefreshToken)
	assert.Equal(t, "oldidtoken", session.IDToken)
	assert.Equal(t, "old@example.com", session.Email)
	assert.Equal(t, "olduser", session.User)
	assert.Equal(t, []string{"oldgroup"}, session.Groups)
	assert.Equal(t, "oldpreferred", session.PreferredUsername)

	assert.Equal(t, testClientAssertion, captured.form.Get("client_assertion"))
	assert.Equal(t, clientAssertionTypeJWTBearer, captured.form.Get("client_assertion_type"))
	assert.Equal(t, "refresh_token", captured.form.Get("grant_type"))
	assert.Empty(t, captured.form.Get("client_secret"))
	assert.Empty(t, captured.authorization)
}

func TestOIDCProviderRedeemWithMissingClientAssertionFile(t *testing.T) {
	server, provider, _ := newAssertionOIDCSetup(t, "/does/not/exist", []byte("{}"))
	defer server.Close()

	_, err := provider.Redeem(context.Background(), "https://example.com/callback", "code1234", "")
	assert.EqualError(t, err, "could not read client assertion file")
}
