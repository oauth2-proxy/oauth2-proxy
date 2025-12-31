package providers

import (
	"context"
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
	internaloidc "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/oidc"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
	admin "google.golang.org/api/admin/directory/v1"
	option "google.golang.org/api/option"
)

// googleOIDCTestRegisteredClaims creates standard JWT claims for Google OIDC provider tests
func googleOIDCTestRegisteredClaims() jwt.RegisteredClaims {
	return jwt.RegisteredClaims{
		Audience:  jwt.ClaimStrings{oidcClientID},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(5) * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Issuer:    oidcIssuer,
		NotBefore: jwt.NewNumericDate(time.Time{}),
		Subject:   "123456789",
	}
}

func newGoogleOIDCRedeemServer(body []byte) (*url.URL, *httptest.Server) {
	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Add("content-type", "application/json")
		rw.Write(body)
	}))
	u, _ := url.Parse(s.URL)
	return u, s
}

func newGoogleOIDCProvider(t *testing.T) *GoogleOIDCProvider {
	g := NewWithT(t)

	verificationOptions := internaloidc.IDTokenVerificationOptions{
		AudienceClaims: []string{"aud"},
		ClientID:       oidcClientID,
	}

	providerData := &ProviderData{
		ProviderName: "",
		LoginURL:     &url.URL{},
		RedeemURL:    &url.URL{},
		ProfileURL:   &url.URL{},
		ValidateURL:  &url.URL{},
		Scope:        "",
		EmailClaim:   "email",
		UserClaim:    "sub",
		Verifier: internaloidc.NewVerifier(oidc.NewVerifier(
			oidcIssuer,
			mockJWKS{},
			&oidc.Config{ClientID: oidcClientID},
		), verificationOptions),
	}

	p := NewGoogleOIDCProvider(providerData, options.GoogleOptions{}, options.OIDCOptions{
		InsecureSkipNonce: func() *bool { b := true; return &b }(),
	})
	g.Expect(p).ToNot(BeNil())
	return p
}

func TestNewGoogleOIDCProvider(t *testing.T) {
	g := NewWithT(t)

	verificationOptions := internaloidc.IDTokenVerificationOptions{
		AudienceClaims: []string{"aud"},
		ClientID:       oidcClientID,
	}

	providerData := &ProviderData{
		Verifier: internaloidc.NewVerifier(oidc.NewVerifier(
			oidcIssuer,
			mockJWKS{},
			&oidc.Config{ClientID: oidcClientID},
		), verificationOptions),
	}

	// Test that defaults are set when calling for a new provider with nothing set
	provider := NewGoogleOIDCProvider(providerData, options.GoogleOptions{}, options.OIDCOptions{})
	g.Expect(provider).ToNot(BeNil())
	g.Expect(provider.Data().ProviderName).To(Equal("Google OIDC"))
}

type googleOIDCRedeemResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token"`
}

func TestGoogleOIDCProviderRedeem(t *testing.T) {
	p := newGoogleOIDCProvider(t)

	idToken, err := newSignedTestIDToken(idTokenClaims{
		Email:            "michael.bland@gsa.gov",
		Verified:         func() *bool { b := true; return &b }(),
		RegisteredClaims: googleOIDCTestRegisteredClaims(),
	})
	assert.NoError(t, err)

	body, err := json.Marshal(googleOIDCRedeemResponse{
		AccessToken:  "a1234",
		ExpiresIn:    10,
		TokenType:    "Bearer",
		RefreshToken: "refresh12345",
		IDToken:      idToken,
	})
	assert.NoError(t, err)

	var server *httptest.Server
	p.RedeemURL, server = newGoogleOIDCRedeemServer(body)
	defer server.Close()

	session, err := p.Redeem(context.Background(), "http://redirect/", "code1234", "")
	assert.NoError(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, "michael.bland@gsa.gov", session.Email)
	assert.Equal(t, "a1234", session.AccessToken)
	assert.Equal(t, "refresh12345", session.RefreshToken)
	assert.Equal(t, idToken, session.IDToken)
}

func TestGoogleOIDCProviderRedeemWithInvalidToken(t *testing.T) {
	p := newGoogleOIDCProvider(t)

	body, err := json.Marshal(googleOIDCRedeemResponse{
		AccessToken:  "a1234",
		ExpiresIn:    10,
		TokenType:    "Bearer",
		RefreshToken: "refresh12345",
		IDToken:      "invalid.token.format",
	})
	assert.NoError(t, err)

	var server *httptest.Server
	p.RedeemURL, server = newGoogleOIDCRedeemServer(body)
	defer server.Close()

	session, err := p.Redeem(context.Background(), "http://redirect/", "code1234", "")
	assert.Error(t, err)
	assert.Nil(t, session)
}

func TestGoogleOIDCProviderRedeemWithMissingIDToken(t *testing.T) {
	p := newGoogleOIDCProvider(t)

	body, err := json.Marshal(googleOIDCRedeemResponse{
		AccessToken:  "a1234",
		ExpiresIn:    10,
		TokenType:    "Bearer",
		RefreshToken: "refresh12345",
		// No IDToken
	})
	assert.NoError(t, err)

	var server *httptest.Server
	p.RedeemURL, server = newGoogleOIDCRedeemServer(body)
	defer server.Close()

	session, err := p.Redeem(context.Background(), "http://redirect/", "code1234", "")
	assert.Error(t, err)
	assert.Nil(t, session)
}

func TestGoogleOIDCProviderValidateSession(t *testing.T) {
	p := newGoogleOIDCProvider(t)

	// Create a valid signed ID token
	idToken, err := newSignedTestIDToken(idTokenClaims{
		Email:            "test@example.com",
		Verified:         func() *bool { b := true; return &b }(),
		RegisteredClaims: googleOIDCTestRegisteredClaims(),
	})
	assert.NoError(t, err)

	testCases := map[string]struct {
		session  *sessions.SessionState
		expected bool
	}{
		"Valid session with ID token": {
			session: &sessions.SessionState{
				IDToken: idToken,
				Email:   "test@example.com",
			},
			expected: true,
		},
		"Invalid session without ID token": {
			session: &sessions.SessionState{
				Email: "test@example.com",
			},
			expected: false,
		},
		"Invalid session with malformed ID token": {
			session: &sessions.SessionState{
				IDToken: "invalid.token",
				Email:   "test@example.com",
			},
			expected: false,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			result := p.ValidateSession(context.Background(), tc.session)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGoogleOIDCProviderGetLoginURL(t *testing.T) {
	p := newGoogleOIDCProvider(t)
	p.LoginURL = &url.URL{
		Scheme: "https",
		Host:   "accounts.google.com",
		Path:   "/o/oauth2/v2/auth",
	}

	loginURL := p.GetLoginURL("http://redirect/", "state123", "nonce456", url.Values{})

	// Verify access_type=offline is added for refresh tokens
	assert.Contains(t, loginURL, "access_type=offline")
	assert.Contains(t, loginURL, "state=state123")
}

func TestGoogleOIDCProvider_getUserGroups(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/directory/v1/groups" && r.URL.Query().Get("userKey") == "test@example.com" {
			response := `{
				"kind": "admin#directory#groups",
				"groups": [
					{
						"kind": "admin#directory#group",
						"id": "1",
						"email": "group1@example.com",
						"name": "Group 1"
					},
					{
						"kind": "admin#directory#group", 
						"id": "2",
						"email": "group2@example.com",
						"name": "Group 2"
					}
				]
			}`
			fmt.Fprintln(w, response)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	client := &http.Client{}
	adminService, err := admin.NewService(context.Background(), option.WithHTTPClient(client), option.WithEndpoint(ts.URL))
	assert.NoError(t, err)

	groups, err := getUserGroups(adminService, "test@example.com")
	assert.NoError(t, err)
	assert.Equal(t, []string{"group1@example.com", "group2@example.com"}, groups)
}

func TestGoogleOIDCProvider_EnrichSessionWithoutAdminService(t *testing.T) {
	const sessionEmail = "test@example.com"

	p := newGoogleOIDCProvider(t)
	// No adminService configured - groups should not be populated

	idToken, err := newSignedTestIDToken(idTokenClaims{
		Email:            sessionEmail,
		Verified:         func() *bool { b := true; return &b }(),
		RegisteredClaims: googleOIDCTestRegisteredClaims(),
	})
	assert.NoError(t, err)

	session := &sessions.SessionState{
		Email:   sessionEmail,
		IDToken: idToken,
	}

	err = p.EnrichSession(context.Background(), session)
	assert.NoError(t, err)
	assert.Nil(t, session.Groups) // No groups populated without adminService
}

func TestGoogleOIDCProvider_RefreshSessionWithoutAdminService(t *testing.T) {
	const sessionEmail = "test@example.com"

	p := newGoogleOIDCProvider(t)
	// No adminService configured

	idToken, err := newSignedTestIDToken(idTokenClaims{
		Email:            sessionEmail,
		Verified:         func() *bool { b := true; return &b }(),
		RegisteredClaims: googleOIDCTestRegisteredClaims(),
	})
	assert.NoError(t, err)

	// Create mock redeem server for refresh
	body, err := json.Marshal(googleOIDCRedeemResponse{
		AccessToken:  "new_access_token",
		ExpiresIn:    3600,
		TokenType:    "Bearer",
		RefreshToken: "new_refresh_token",
		IDToken:      idToken,
	})
	assert.NoError(t, err)

	var server *httptest.Server
	p.RedeemURL, server = newGoogleOIDCRedeemServer(body)
	defer server.Close()

	session := &sessions.SessionState{
		Email:        sessionEmail,
		IDToken:      idToken,
		RefreshToken: "old_refresh_token",
	}

	refreshed, err := p.RefreshSession(context.Background(), session)
	assert.NoError(t, err)
	assert.True(t, refreshed)
}

func TestGoogleOIDCProvider_CreateSessionFromToken(t *testing.T) {
	const sessionEmail = "test@example.com"

	p := newGoogleOIDCProvider(t)

	idToken, err := newSignedTestIDToken(idTokenClaims{
		Email:            sessionEmail,
		Verified:         func() *bool { b := true; return &b }(),
		RegisteredClaims: googleOIDCTestRegisteredClaims(),
	})
	assert.NoError(t, err)

	session, err := p.CreateSessionFromToken(context.Background(), idToken)
	assert.NoError(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, sessionEmail, session.Email)
	assert.Equal(t, idToken, session.IDToken)
	// No adminService configured, so groups should be nil
	assert.Nil(t, session.Groups)
}

func TestGoogleOIDCProvider_CreateSessionFromTokenWithInvalidToken(t *testing.T) {
	p := newGoogleOIDCProvider(t)

	session, err := p.CreateSessionFromToken(context.Background(), "invalid.token")
	assert.Error(t, err)
	assert.Nil(t, session)
}
