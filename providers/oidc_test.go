package providers

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
	internaloidc "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type redeemTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token,omitempty"`
}

func newOIDCProvider(serverURL *url.URL, skipNonce bool) *OIDCProvider {
	verificationOptions := internaloidc.IDTokenVerificationOptions{
		AudienceClaims: []string{"aud"},
		ClientID:       "https://test.myapp.com",
	}
	providerData := &ProviderData{
		ProviderName: "oidc",
		ClientID:     oidcClientID,
		ClientSecret: oidcSecret,
		LoginURL: &url.URL{
			Scheme: serverURL.Scheme,
			Host:   serverURL.Host,
			Path:   "/login/oauth/authorize"},
		RedeemURL: &url.URL{
			Scheme: serverURL.Scheme,
			Host:   serverURL.Host,
			Path:   "/login/oauth/access_token"},
		ProfileURL: &url.URL{
			Scheme: serverURL.Scheme,
			Host:   serverURL.Host,
			Path:   "/profile"},
		ValidateURL: &url.URL{
			Scheme: serverURL.Scheme,
			Host:   serverURL.Host,
			Path:   "/api"},
		Scope:       "openid profile offline_access",
		EmailClaim:  "email",
		GroupsClaim: "groups",
		UserClaim:   "sub",
		Verifier: internaloidc.NewVerifier(oidc.NewVerifier(
			oidcIssuer,
			mockJWKS{},
			&oidc.Config{ClientID: oidcClientID},
		), verificationOptions),
	}

	p := NewOIDCProvider(providerData, options.OIDCOptions{
		InsecureSkipNonce: &skipNonce,
	})

	return p
}

func newOIDCServer(body []byte) (*url.URL, *httptest.Server) {
	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Add("content-type", "application/json")
		_, _ = rw.Write(body)
	}))
	u, _ := url.Parse(s.URL)
	return u, s
}

func newTestOIDCSetup(body []byte) (*httptest.Server, *OIDCProvider) {
	redeemURL, server := newOIDCServer(body)
	provider := newOIDCProvider(redeemURL, false)
	return server, provider
}

func TestOIDCProviderGetLoginURL(t *testing.T) {
	serverURL := &url.URL{
		Scheme: "https",
		Host:   "oauth2proxy.oidctest",
	}
	provider := newOIDCProvider(serverURL, true)

	n, err := encryption.Nonce(32)
	assert.NoError(t, err)
	nonce := base64.RawURLEncoding.EncodeToString(n)

	// SkipNonce defaults to true
	skipNonce := provider.GetLoginURL("http://redirect/", "", nonce, url.Values{})
	assert.NotContains(t, skipNonce, "nonce")

	provider.SkipNonce = false
	withNonce := provider.GetLoginURL("http://redirect/", "", nonce, url.Values{})
	assert.Contains(t, withNonce, fmt.Sprintf("nonce=%s", nonce))
	assert.NotContains(t, withNonce, "code_challenge")
	assert.NotContains(t, withNonce, "code_challenge_method")
}

func TestOIDCProviderRedeem(t *testing.T) {
	idToken, _ := newSignedTestIDToken(defaultIDToken)
	body, _ := json.Marshal(redeemTokenResponse{
		AccessToken:  accessToken,
		ExpiresIn:    10,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		IDToken:      idToken,
	})

	server, provider := newTestOIDCSetup(body)
	defer server.Close()

	session, err := provider.Redeem(context.Background(), provider.RedeemURL.String(), "code1234", "")
	assert.Equal(t, nil, err)
	assert.Equal(t, defaultIDToken.Email, session.Email)
	assert.Equal(t, accessToken, session.AccessToken)
	assert.Equal(t, idToken, session.IDToken)
	assert.Equal(t, refreshToken, session.RefreshToken)
	assert.Equal(t, "123456789", session.User)
}

func TestOIDCProviderRedeem_custom_userid(t *testing.T) {
	idToken, _ := newSignedTestIDToken(defaultIDToken)
	body, _ := json.Marshal(redeemTokenResponse{
		AccessToken:  accessToken,
		ExpiresIn:    10,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		IDToken:      idToken,
	})

	server, provider := newTestOIDCSetup(body)
	provider.EmailClaim = "phone_number"
	defer server.Close()

	session, err := provider.Redeem(context.Background(), provider.RedeemURL.String(), "code1234", "")
	assert.Equal(t, nil, err)
	assert.Equal(t, defaultIDToken.Phone, session.Email)
}

func TestOIDCProviderRefreshSessionIfNeededWithoutIdToken(t *testing.T) {

	idToken, _ := newSignedTestIDToken(defaultIDToken)
	body, _ := json.Marshal(redeemTokenResponse{
		AccessToken:  accessToken,
		ExpiresIn:    10,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
	})

	server, provider := newTestOIDCSetup(body)
	defer server.Close()

	existingSession := &sessions.SessionState{
		AccessToken:  "changeit",
		IDToken:      idToken,
		CreatedAt:    nil,
		ExpiresOn:    nil,
		RefreshToken: refreshToken,
		Email:        "janedoe@example.com",
		User:         "11223344",
	}

	refreshed, err := provider.RefreshSession(context.Background(), existingSession)
	assert.Equal(t, nil, err)
	assert.Equal(t, refreshed, true)
	assert.Equal(t, "janedoe@example.com", existingSession.Email)
	assert.Equal(t, accessToken, existingSession.AccessToken)
	assert.Equal(t, idToken, existingSession.IDToken)
	assert.Equal(t, refreshToken, existingSession.RefreshToken)
	assert.Equal(t, "11223344", existingSession.User)
}

func TestOIDCProviderRefreshSessionIfNeededWithIdToken(t *testing.T) {

	idToken, _ := newSignedTestIDToken(defaultIDToken)
	body, _ := json.Marshal(redeemTokenResponse{
		AccessToken:  accessToken,
		ExpiresIn:    10,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		IDToken:      idToken,
	})

	server, provider := newTestOIDCSetup(body)
	defer server.Close()

	existingSession := &sessions.SessionState{
		AccessToken:  "changeit",
		IDToken:      "changeit",
		Nonce:        []byte(oidcNonce),
		CreatedAt:    nil,
		ExpiresOn:    nil,
		RefreshToken: refreshToken,
		Email:        "changeit",
		User:         "changeit",
	}
	refreshed, err := provider.RefreshSession(context.Background(), existingSession)
	assert.Equal(t, nil, err)
	assert.Equal(t, refreshed, true)
	assert.Equal(t, defaultIDToken.Email, existingSession.Email)
	assert.Equal(t, defaultIDToken.Subject, existingSession.User)
	assert.Equal(t, accessToken, existingSession.AccessToken)
	assert.Equal(t, idToken, existingSession.IDToken)
	assert.Equal(t, refreshToken, existingSession.RefreshToken)
}

func TestOIDCProviderRefreshSessionIfNeededWithIdTokenUpdatesAdditionalClaims(t *testing.T) {
	idToken, _ := newSignedTestIDToken(defaultIDToken)
	body, _ := json.Marshal(redeemTokenResponse{
		AccessToken:  accessToken,
		ExpiresIn:    10,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		IDToken:      idToken,
	})

	server, provider := newTestOIDCSetup(body)
	provider.AdditionalClaims = []string{"phone_number"}
	defer server.Close()

	existingSession := &sessions.SessionState{
		AccessToken:  "changeit",
		IDToken:      "changeit",
		RefreshToken: refreshToken,
		AdditionalClaims: map[string]interface{}{
			"phone_number": "stale",
		},
		Nonce: []byte(oidcNonce),
	}

	refreshed, err := provider.RefreshSession(context.Background(), existingSession)
	assert.Equal(t, nil, err)
	assert.Equal(t, refreshed, true)
	assert.Equal(t, defaultIDToken.Phone, existingSession.AdditionalClaims["phone_number"])
}

func TestOIDCProviderRefreshSessionNonce(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	untrustedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	for _, providerName := range []string{"oidc", "keycloak"} {
		for _, tc := range []struct {
			name                string
			nonce               any
			skipNonce           bool
			omitIDToken         bool
			expired             bool
			missingSessionNonce bool
			invalidSignature    bool
			wantError           string
		}{
			{name: "missing nonce"},
			{name: "matching nonce", nonce: defaultIDToken.Nonce},
			{name: "mismatched nonce", nonce: "wrong", wantError: "nonce claim does not match"},
			{name: "empty nonce", nonce: "", wantError: "nonce claim does not match"},
			{name: "null nonce", nonce: (*string)(nil), wantError: "nonce claim does not match"},
			{name: "empty nonce without session nonce", nonce: "", missingSessionNonce: true, wantError: "nonce claim does not match"},
			{name: "null nonce without session nonce", nonce: (*string)(nil), missingSessionNonce: true, wantError: "nonce claim does not match"},
			{name: "non-string nonce", nonce: 42, wantError: "could not verify id_token"},
			{name: "nonce check disabled", nonce: "wrong", skipNonce: true},
			{name: "missing ID token", omitIDToken: true},
			{name: "expired ID token", expired: true, wantError: "token is expired"},
			{name: "invalid signature", nonce: defaultIDToken.Nonce, invalidSignature: true, wantError: "failed to verify signature"},
			{name: "invalid signature with nonce check disabled", skipNonce: true, invalidSignature: true, wantError: "failed to verify signature"},
		} {
			t.Run(providerName+"/"+tc.name, func(t *testing.T) {
				claims := struct {
					idTokenClaims
					Nonce any `json:"nonce,omitempty"`
				}{idTokenClaims: defaultIDToken, Nonce: tc.nonce}
				if tc.expired {
					claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
				}
				signingKey := key
				if tc.invalidSignature {
					signingKey = untrustedKey
				}
				rawIDToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(signingKey)
				require.NoError(t, err)
				if tc.omitIDToken {
					rawIDToken = ""
				}
				refreshedAccessToken := makeAccessToken()
				body, err := json.Marshal(redeemTokenResponse{
					AccessToken: refreshedAccessToken, RefreshToken: refreshToken,
					ExpiresIn: 3600, TokenType: "Bearer", IDToken: rawIDToken,
				})
				require.NoError(t, err)
				server, provider := newTestOIDCSetup(body)
				defer server.Close()
				provider.SkipNonce = tc.skipNonce
				provider.Verifier = internaloidc.NewVerifier(oidc.NewVerifier(
					oidcIssuer, &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{key.Public()}},
					&oidc.Config{ClientID: oidcClientID},
				), internaloidc.IDTokenVerificationOptions{ClientID: oidcClientID, AudienceClaims: []string{"aud"}})
				provider.ValidateURL = nil
				var refreshProvider Provider = provider
				if providerName == "keycloak" {
					refreshProvider = &KeycloakOIDCProvider{OIDCProvider: provider}
				}

				originalIDToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, defaultIDToken).SignedString(key)
				require.NoError(t, err)
				session := &sessions.SessionState{
					AccessToken: "original-access-token", IDToken: originalIDToken,
					RefreshToken: refreshToken, Nonce: []byte(oidcNonce),
				}
				if tc.missingSessionNonce {
					session.Nonce = nil
				}
				original := *session
				refreshed, err := refreshProvider.RefreshSession(context.Background(), session)
				if tc.wantError != "" {
					require.ErrorContains(t, err, tc.wantError)
					assert.False(t, refreshed)
					assert.Equal(t, original, *session, "invalid tokens must not replace the stored session")
					return
				}
				require.NoError(t, err)
				assert.True(t, refreshed)
				assert.Equal(t, refreshedAccessToken, session.AccessToken)
				assert.Equal(t, original.Nonce, session.Nonce)
				if tc.omitIDToken {
					assert.Equal(t, originalIDToken, session.IDToken)
				} else {
					assert.Equal(t, rawIDToken, session.IDToken)
				}
				assert.True(t, provider.ValidateSession(context.Background(), session))
			})
		}
	}
}

func TestOIDCProviderValidateSessionNonce(t *testing.T) {
	for _, tc := range []struct {
		name      string
		nonce     string
		skipNonce bool
		valid     bool
	}{
		{name: "matching nonce", nonce: defaultIDToken.Nonce, valid: true},
		{name: "missing nonce"},
		{name: "mismatched nonce", nonce: "wrong"},
		{name: "nonce check disabled", skipNonce: true, valid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := defaultIDToken
			claims.Nonce = tc.nonce
			rawIDToken, err := newSignedTestIDToken(claims)
			require.NoError(t, err)
			server, provider := newTestOIDCSetup([]byte(`{}`))
			defer server.Close()
			provider.SkipNonce = tc.skipNonce
			session := &sessions.SessionState{IDToken: rawIDToken, Nonce: []byte(oidcNonce)}
			assert.Equal(t, tc.valid, provider.ValidateSession(context.Background(), session))
		})
	}
}

func TestOIDCProviderCreateSessionFromToken(t *testing.T) {
	testCases := map[string]struct {
		IDToken        idTokenClaims
		GroupsClaim    string
		ExpectedUser   string
		ExpectedEmail  string
		ExpectedGroups []string
	}{
		"Default IDToken": {
			IDToken:        defaultIDToken,
			GroupsClaim:    "groups",
			ExpectedUser:   "123456789",
			ExpectedEmail:  "janed@me.com",
			ExpectedGroups: []string{"test:a", "test:b"},
		},
		"Minimal IDToken with no email claim": {
			IDToken:        minimalIDToken,
			GroupsClaim:    "groups",
			ExpectedUser:   "123456789",
			ExpectedEmail:  "123456789",
			ExpectedGroups: nil,
		},
		"Custom Groups Claim": {
			IDToken:        defaultIDToken,
			GroupsClaim:    "roles",
			ExpectedUser:   "123456789",
			ExpectedEmail:  "janed@me.com",
			ExpectedGroups: []string{"test:c", "test:d"},
		},
		"Complex Groups Claim": {
			IDToken:       complexGroupsIDToken,
			GroupsClaim:   "groups",
			ExpectedUser:  "123456789",
			ExpectedEmail: "complex@claims.com",
			ExpectedGroups: []string{
				"{\"groupId\":\"Admin Group Id\",\"roles\":[\"Admin\"]}",
				"12345",
				"Just::A::String",
			},
		},
	}
	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			server, provider := newTestOIDCSetup([]byte(`{}`))
			provider.GroupsClaim = tc.GroupsClaim
			defer server.Close()

			rawIDToken, err := newSignedTestIDToken(tc.IDToken)
			assert.NoError(t, err)

			ss, err := provider.CreateSessionFromToken(context.Background(), rawIDToken)
			assert.NoError(t, err)

			assert.Equal(t, tc.ExpectedUser, ss.User)
			assert.Equal(t, tc.ExpectedEmail, ss.Email)
			assert.Equal(t, tc.ExpectedGroups, ss.Groups)
			assert.Equal(t, rawIDToken, ss.IDToken)
			assert.Equal(t, rawIDToken, ss.AccessToken)
			assert.Equal(t, "", ss.RefreshToken)
		})
	}
}

func TestOIDCProviderResponseModeConfigured(t *testing.T) {
	providerData := &ProviderData{
		LoginURL: &url.URL{
			Scheme: "http",
			Host:   "my.test.idp",
			Path:   "/oauth/authorize",
		},
		AuthRequestResponseMode: "form_post",
	}
	p := NewOIDCProvider(providerData, options.OIDCOptions{})

	result := p.GetLoginURL("https://my.test.app/oauth", "", "", url.Values{})
	assert.Contains(t, result, "response_mode=form_post")
}

func TestOIDCProviderResponseModeNotConfigured(t *testing.T) {
	providerData := &ProviderData{
		LoginURL: &url.URL{
			Scheme: "http",
			Host:   "my.test.idp",
			Path:   "/oauth/authorize",
		},
	}
	p := NewOIDCProvider(providerData, options.OIDCOptions{})

	result := p.GetLoginURL("https://my.test.app/oauth", "", "", url.Values{})
	assert.NotContains(t, result, "response_mode")
}
