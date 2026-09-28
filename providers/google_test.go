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

// googleTestRegisteredClaims creates standard JWT claims for Google provider tests
func googleTestRegisteredClaims() jwt.RegisteredClaims {
	return jwt.RegisteredClaims{
		Audience:  jwt.ClaimStrings{oidcClientID},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(5) * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Issuer:    oidcIssuer,
		NotBefore: jwt.NewNumericDate(time.Time{}),
		Subject:   "123456789",
	}
}

func newGoogleRedeemServer(body []byte) (*url.URL, *httptest.Server) {
	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Add("content-type", "application/json")
		rw.Write(body)
	}))
	u, _ := url.Parse(s.URL)
	return u, s
}

func newGoogleProvider(t *testing.T) *GoogleProvider {
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

	p := NewGoogleProvider(providerData, options.GoogleOptions{}, options.OIDCOptions{
		InsecureSkipNonce: func() *bool { b := true; return &b }(),
	})
	g.Expect(p).ToNot(BeNil())
	return p
}

func TestNewGoogleProvider(t *testing.T) {
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
	provider := NewGoogleProvider(providerData, options.GoogleOptions{}, options.OIDCOptions{})
	g.Expect(provider).ToNot(BeNil())
	g.Expect(provider.Data().ProviderName).To(Equal("Google"))
	g.Expect(provider.Data().Scope).To(Equal("openid email profile"))
}

type googleRedeemResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token"`
}

func TestGoogleProviderRedeem(t *testing.T) {
	p := newGoogleProvider(t)

	idToken, err := newSignedTestIDToken(idTokenClaims{
		Email:            "michael.bland@gsa.gov",
		Verified:         func() *bool { b := true; return &b }(),
		RegisteredClaims: googleTestRegisteredClaims(),
	})
	assert.NoError(t, err)

	body, err := json.Marshal(googleRedeemResponse{
		AccessToken:  "a1234",
		ExpiresIn:    10,
		TokenType:    "Bearer",
		RefreshToken: "refresh12345",
		IDToken:      idToken,
	})
	assert.NoError(t, err)

	var server *httptest.Server
	p.RedeemURL, server = newGoogleRedeemServer(body)
	defer server.Close()

	session, err := p.Redeem(context.Background(), "http://redirect/", "code1234", "")
	assert.NoError(t, err)
	assert.NotNil(t, session)
	assert.Equal(t, "michael.bland@gsa.gov", session.Email)
	assert.Equal(t, "a1234", session.AccessToken)
	assert.Equal(t, "refresh12345", session.RefreshToken)
	assert.Equal(t, idToken, session.IDToken)
}

func TestGoogleProviderRedeemWithInvalidToken(t *testing.T) {
	p := newGoogleProvider(t)

	body, err := json.Marshal(googleRedeemResponse{
		AccessToken:  "a1234",
		ExpiresIn:    10,
		TokenType:    "Bearer",
		RefreshToken: "refresh12345",
		IDToken:      "invalid.token.format",
	})
	assert.NoError(t, err)

	var server *httptest.Server
	p.RedeemURL, server = newGoogleRedeemServer(body)
	defer server.Close()

	session, err := p.Redeem(context.Background(), "http://redirect/", "code1234", "")
	assert.Error(t, err)
	assert.Nil(t, session)
}

func TestGoogleProviderRedeemWithMissingIDToken(t *testing.T) {
	p := newGoogleProvider(t)

	body, err := json.Marshal(googleRedeemResponse{
		AccessToken:  "a1234",
		ExpiresIn:    10,
		TokenType:    "Bearer",
		RefreshToken: "refresh12345",
		// No IDToken
	})
	assert.NoError(t, err)

	var server *httptest.Server
	p.RedeemURL, server = newGoogleRedeemServer(body)
	defer server.Close()

	session, err := p.Redeem(context.Background(), "http://redirect/", "code1234", "")
	assert.Error(t, err)
	assert.Nil(t, session)
}

func TestGoogleProviderValidateSession(t *testing.T) {
	p := newGoogleProvider(t)

	// Create a valid signed ID token
	idToken, err := newSignedTestIDToken(idTokenClaims{
		Email:            "test@example.com",
		Verified:         func() *bool { b := true; return &b }(),
		RegisteredClaims: googleTestRegisteredClaims(),
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

func TestGoogleProviderGetLoginURL(t *testing.T) {
	p := newGoogleProvider(t)
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

func TestGoogleProviderGroupValidator(t *testing.T) {
	const sessionEmail = "michael.bland@gsa.gov"

	testCases := map[string]struct {
		session       *sessions.SessionState
		validatorFunc func(*sessions.SessionState) bool
		expectedAuthZ bool
	}{
		"Email is authorized with groupValidator": {
			session: &sessions.SessionState{
				Email: sessionEmail,
			},
			validatorFunc: func(s *sessions.SessionState) bool {
				return s.Email == sessionEmail
			},
			expectedAuthZ: true,
		},
		"Email is denied with groupValidator": {
			session: &sessions.SessionState{
				Email: sessionEmail,
			},
			validatorFunc: func(s *sessions.SessionState) bool {
				return s.Email != sessionEmail
			},
			expectedAuthZ: false,
		},
		"Default does no authorization checks": {
			session: &sessions.SessionState{
				Email: sessionEmail,
			},
			validatorFunc: nil,
			expectedAuthZ: true,
		},
	}
	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			g := NewWithT(t)
			p := newGoogleProvider(t)
			if tc.validatorFunc != nil {
				p.groupValidator = tc.validatorFunc
			}
			g.Expect(p.groupValidator(tc.session)).To(Equal(tc.expectedAuthZ))
		})
	}
}

func TestGoogleProvider_userInGroup(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/directory/v1/groups/group@example.com/hasMember/member-in-domain@example.com":
			fmt.Fprintln(w, `{"isMember":true}`)
		case "/admin/directory/v1/groups/group@example.com/hasMember/non-member-in-domain@example.com":
			fmt.Fprintln(w, `{"isMember":false}`)
		case "/admin/directory/v1/groups/group@example.com/hasMember/member-out-of-domain@otherexample.com":
			http.Error(
				w,
				`{"error":{"errors":[{"domain":"global","reason":"invalid","message":"Invalid Input: memberKey"}],"code":400,"message":"Invalid Input: memberKey"}}`,
				http.StatusBadRequest,
			)
		case "/admin/directory/v1/groups/group@example.com/hasMember/non-member-out-of-domain@otherexample.com":
			http.Error(
				w,
				`{"error":{"errors":[{"domain":"global","reason":"invalid","message":"Invalid Input: memberKey"}],"code":400,"message":"Invalid Input: memberKey"}}`,
				http.StatusBadRequest,
			)
		case "/admin/directory/v1/groups/group@example.com/members/non-member-out-of-domain@otherexample.com":
			// note that the client currently doesn't care what this response text or code is - any error here results in failure to match the group
			http.Error(
				w,
				`{"kind":"admin#directory#member","etag":"12345","id":"1234567890","email":"member-out-of-domain@otherexample.com","role":"MEMBER","type":"USER","status":"ACTIVE","delivery_settings":"ALL_MAIL"}`,
				http.StatusNotFound,
			)
		case "/admin/directory/v1/groups/group@example.com/members/member-out-of-domain@otherexample.com":
			fmt.Fprintln(w,
				`{"kind":"admin#directory#member","etag":"12345","id":"1234567890","email":"member-out-of-domain@otherexample.com","role":"MEMBER","type":"USER","status":"ACTIVE","delivery_settings":"ALL_MAIL"}`,
			)
		}
	}))
	defer ts.Close()

	client := ts.Client()
	ctx := context.Background()

	service, err := admin.NewService(ctx, option.WithHTTPClient(client))
	assert.NoError(t, err)

	service.BasePath = ts.URL

	result := userInGroup(service, "group@example.com", "member-in-domain@example.com")
	assert.True(t, result)

	result = userInGroup(service, "group@example.com", "member-out-of-domain@otherexample.com")
	assert.True(t, result)

	result = userInGroup(service, "group@example.com", "non-member-in-domain@example.com")
	assert.False(t, result)

	result = userInGroup(service, "group@example.com", "non-member-out-of-domain@otherexample.com")
	assert.False(t, result)
}

func TestGoogleProvider_getUserGroups(t *testing.T) {
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

func TestGoogleProvider_getUserInfo(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin/directory/v1/users/test@example.com" {
			response := `{
			  "kind": "admin#directory#user",
			  "id": "",
			  "etag": "\"\"",
			  "primaryEmail": "test@example.com",
			  "name": {
				"givenName": "Test",
				"familyName": "User",
				"fullName": "Test User"
			  },
			  "isAdmin": false,
			  "isDelegatedAdmin": false,
			  "lastLoginTime": "",
			  "creationTime": "",
			  "agreedToTerms": true,
			  "suspended": false,
			  "archived": false,
			  "changePasswordAtNextLogin": false,
			  "ipWhitelisted": false,
			  "emails": [
				{
				  "address": "test@example.com",
				  "primary": true
				}
			  ],
			  "externalIds": [
				{
				  "value": "test.user",
				  "type": "organization"
				}
			  ],
			  "organizations": [
			  ],
			  "phones": [
			  ],
			  "languages": [
				{
				  "languageCode": "en",
				  "preference": "preferred"
				}
			  ],
			  "aliases": [
				"test.user@example.com"
			  ],
			  "nonEditableAliases": [
				"test.user@example.com"
			  ],
			  "gender": {
				"type": "male"
			  },
			  "customerId": "",
			  "orgUnitPath": "/",
			  "isMailboxSetup": true,
			  "isEnrolledIn2Sv": true,
			  "isEnforcedIn2Sv": false,
			  "includeInGlobalAddressList": true,
			  "thumbnailPhotoUrl": "",
			  "thumbnailPhotoEtag": "\"\"",
			  "recoveryEmail": "test.user@gmail.com",
			  "recoveryPhone": "+55555555555"
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

	info, err := getUserInfo(adminService, "test@example.com")
	assert.NoError(t, err)
	assert.Equal(t, "test.user", info)
}

func TestGoogleProvider_EnrichSessionWithoutAdminService(t *testing.T) {
	const sessionEmail = "test@example.com"

	p := newGoogleProvider(t)
	// No adminService configured - groups should not be populated

	idToken, err := newSignedTestIDToken(idTokenClaims{
		Email:            sessionEmail,
		Verified:         func() *bool { b := true; return &b }(),
		RegisteredClaims: googleTestRegisteredClaims(),
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

func TestGoogleProvider_RefreshSessionWithoutAdminService(t *testing.T) {
	const sessionEmail = "test@example.com"

	p := newGoogleProvider(t)
	// No adminService configured

	idToken, err := newSignedTestIDToken(idTokenClaims{
		Email:            sessionEmail,
		Verified:         func() *bool { b := true; return &b }(),
		RegisteredClaims: googleTestRegisteredClaims(),
	})
	assert.NoError(t, err)

	// Create mock redeem server for refresh
	body, err := json.Marshal(googleRedeemResponse{
		AccessToken:  "new_access_token",
		ExpiresIn:    3600,
		TokenType:    "Bearer",
		RefreshToken: "new_refresh_token",
		IDToken:      idToken,
	})
	assert.NoError(t, err)

	var server *httptest.Server
	p.RedeemURL, server = newGoogleRedeemServer(body)
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

func TestGoogleProvider_CreateSessionFromToken(t *testing.T) {
	const sessionEmail = "test@example.com"

	p := newGoogleProvider(t)

	idToken, err := newSignedTestIDToken(idTokenClaims{
		Email:            sessionEmail,
		Verified:         func() *bool { b := true; return &b }(),
		RegisteredClaims: googleTestRegisteredClaims(),
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

func TestGoogleProvider_CreateSessionFromTokenWithInvalidToken(t *testing.T) {
	p := newGoogleProvider(t)

	session, err := p.CreateSessionFromToken(context.Background(), "invalid.token")
	assert.Error(t, err)
	assert.Nil(t, session)
}
