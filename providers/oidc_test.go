package providers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

const accessToken = "access_token"
const refreshToken = "refresh_token"
const clientID = "https://test.myapp.com"
const secret = "secret"

type idTokenClaims struct {
	Name        string      `json:"name,omitempty"`
	Email       string      `json:"email,omitempty"`
	Phone       string      `json:"phone_number,omitempty"`
	Picture     string      `json:"picture,omitempty"`
	Groups      interface{} `json:"groups,omitempty"`
	OtherGroups interface{} `json:"other_groups,omitempty"`
	jwt.StandardClaims
}

type redeemTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token,omitempty"`
}

var defaultIDToken idTokenClaims = idTokenClaims{
	"Jane Dobbs",
	"janed@me.com",
	"+4798765432",
	"http://mugbook.com/janed/me.jpg",
	[]string{"test:a", "test:b"},
	[]string{"test:c", "test:d"},
	jwt.StandardClaims{
		Audience:  "https://test.myapp.com",
		ExpiresAt: time.Now().Add(time.Duration(5) * time.Minute).Unix(),
		Id:        "id-some-id",
		IssuedAt:  time.Now().Unix(),
		Issuer:    "https://issuer.example.com",
		NotBefore: 0,
		Subject:   "123456789",
	},
}

var customGroupClaimIDToken idTokenClaims = idTokenClaims{
	"Jane Dobbs",
	"janed@me.com",
	"+4798765432",
	"http://mugbook.com/janed/me.jpg",
	[]map[string]interface{}{
		{
			"groupId": "Admin Group Id",
			"roles":   []string{"Admin"},
		},
	},
	[]string{"test:c", "test:d"},
	jwt.StandardClaims{
		Audience:  "https://test.myapp.com",
		ExpiresAt: time.Now().Add(time.Duration(5) * time.Minute).Unix(),
		Id:        "id-some-id",
		IssuedAt:  time.Now().Unix(),
		Issuer:    "https://issuer.example.com",
		NotBefore: 0,
		Subject:   "123456789",
	},
}

var minimalIDToken idTokenClaims = idTokenClaims{
	"",
	"",
	"",
	"",
	[]string{},
	[]string{},
	jwt.StandardClaims{
		Audience:  "https://test.myapp.com",
		ExpiresAt: time.Now().Add(time.Duration(5) * time.Minute).Unix(),
		Id:        "id-some-id",
		IssuedAt:  time.Now().Unix(),
		Issuer:    "https://issuer.example.com",
		NotBefore: 0,
		Subject:   "minimal",
	},
}

type fakeKeySetStub struct{}

func (fakeKeySetStub) VerifySignature(_ context.Context, jwt string) (payload []byte, err error) {
	decodeString, err := base64.RawURLEncoding.DecodeString(strings.Split(jwt, ".")[1])
	if err != nil {
		return nil, err
	}
	tokenClaims := &idTokenClaims{}
	err = json.Unmarshal(decodeString, tokenClaims)

	if err != nil || tokenClaims.Id == "this-id-fails-validation" {
		return nil, fmt.Errorf("the validation failed for subject [%v]", tokenClaims.Subject)
	}

	return decodeString, err
}

func newOIDCProvider(serverURL *url.URL) *OIDCProvider {

	providerData := &ProviderData{
		ProviderName: "oidc",
		ClientID:     clientID,
		ClientSecret: secret,
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
		Scope: "openid profile offline_access",
		Verifier: oidc.NewVerifier(
			"https://issuer.example.com",
			fakeKeySetStub{},
			&oidc.Config{ClientID: clientID},
		),
	}

	p := &OIDCProvider{
		ProviderData: providerData,
		EmailClaim:   "email",
	}

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

func newSignedTestIDToken(tokenClaims idTokenClaims) (string, error) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	standardClaims := jwt.NewWithClaims(jwt.SigningMethodRS256, tokenClaims)
	return standardClaims.SignedString(key)
}

func newOauth2Token() *oauth2.Token {
	return &oauth2.Token{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		Expiry:       time.Time{}.Add(time.Duration(5) * time.Second),
	}
}

func newTestSetup(body []byte) (*httptest.Server, *OIDCProvider) {
	redeemURL, server := newOIDCServer(body)
	provider := newOIDCProvider(redeemURL)
	return server, provider
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

	server, provider := newTestSetup(body)
	defer server.Close()

	session, err := provider.Redeem(context.Background(), provider.RedeemURL.String(), "code1234")
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

	server, provider := newTestSetup(body)
	provider.EmailClaim = "phone_number"
	defer server.Close()

	session, err := provider.Redeem(context.Background(), provider.RedeemURL.String(), "code1234")
	assert.Equal(t, nil, err)
	assert.Equal(t, defaultIDToken.Phone, session.Email)
}

func TestOIDCProvider_EnrichSession(t *testing.T) {
	const (
		idToken      = "Unchanged ID Token"
		accessToken  = "Unchanged Access Token"
		refreshToken = "Unchanged Refresh Token"
	)

	testCases := map[string]struct {
		ExistingSession *sessions.SessionState
		EmailClaim      string
		GroupsClaim     string
		ProfileJSON     map[string]interface{}
		ExpectedError   error
		ExpectedSession *sessions.SessionState
	}{
		"Already Populated": {
			ExistingSession: &sessions.SessionState{
				User:         "already",
				Email:        "already@populated.com",
				Groups:       []string{"already", "populated"},
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			EmailClaim:  "email",
			GroupsClaim: "groups",
			ProfileJSON: map[string]interface{}{
				"email":  "new@thing.com",
				"groups": []string{"new", "thing"},
			},
			ExpectedError: nil,
			ExpectedSession: &sessions.SessionState{
				User:         "already",
				Email:        "already@populated.com",
				Groups:       []string{"already", "populated"},
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
		},
		"Missing Email": {
			ExistingSession: &sessions.SessionState{
				User:         "missing.email",
				Groups:       []string{"already", "populated"},
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			EmailClaim:  "email",
			GroupsClaim: "groups",
			ProfileJSON: map[string]interface{}{
				"email":  "found@email.com",
				"groups": []string{"new", "thing"},
			},
			ExpectedError: nil,
			ExpectedSession: &sessions.SessionState{
				User:         "missing.email",
				Email:        "found@email.com",
				Groups:       []string{"already", "populated"},
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
		},

		"Missing Email Only in Profile URL": {
			ExistingSession: &sessions.SessionState{
				User:         "missing.email",
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			EmailClaim:  "email",
			GroupsClaim: "groups",
			ProfileJSON: map[string]interface{}{
				"email": "found@email.com",
			},
			ExpectedError: nil,
			ExpectedSession: &sessions.SessionState{
				User:         "missing.email",
				Email:        "found@email.com",
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
		},
		"Missing Email with Custom Claim": {
			ExistingSession: &sessions.SessionState{
				User:         "missing.email",
				Groups:       []string{"already", "populated"},
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			EmailClaim:  "weird",
			GroupsClaim: "groups",
			ProfileJSON: map[string]interface{}{
				"weird":  "weird@claim.com",
				"groups": []string{"new", "thing"},
			},
			ExpectedError: nil,
			ExpectedSession: &sessions.SessionState{
				User:         "missing.email",
				Email:        "weird@claim.com",
				Groups:       []string{"already", "populated"},
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
		},
		"Missing Email not in Profile URL": {
			ExistingSession: &sessions.SessionState{
				User:         "missing.email",
				Groups:       []string{"already", "populated"},
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			EmailClaim:  "email",
			GroupsClaim: "groups",
			ProfileJSON: map[string]interface{}{
				"groups": []string{"new", "thing"},
			},
			ExpectedError: errors.New("neither the id_token nor the profileURL set an email"),
			ExpectedSession: &sessions.SessionState{
				User:         "missing.email",
				Groups:       []string{"already", "populated"},
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
		},
		"Missing Groups": {
			ExistingSession: &sessions.SessionState{
				User:         "already",
				Email:        "already@populated.com",
				Groups:       []string{},
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			EmailClaim:  "email",
			GroupsClaim: "groups",
			ProfileJSON: map[string]interface{}{
				"email":  "new@thing.com",
				"groups": []string{"new", "thing"},
			},
			ExpectedError: nil,
			ExpectedSession: &sessions.SessionState{
				User:         "already",
				Email:        "already@populated.com",
				Groups:       []string{"new", "thing"},
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
		},
		"Missing Groups with Custom Claim": {
			ExistingSession: &sessions.SessionState{
				User:         "already",
				Email:        "already@populated.com",
				Groups:       nil,
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			EmailClaim:  "email",
			GroupsClaim: "roles",
			ProfileJSON: map[string]interface{}{
				"email": "new@thing.com",
				"roles": []string{"new", "thing", "roles"},
			},
			ExpectedError: nil,
			ExpectedSession: &sessions.SessionState{
				User:         "already",
				Email:        "already@populated.com",
				Groups:       []string{"new", "thing", "roles"},
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
		},
		"Missing Groups String Profile URL Response": {
			ExistingSession: &sessions.SessionState{
				User:         "already",
				Email:        "already@populated.com",
				Groups:       []string{},
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			EmailClaim:  "email",
			GroupsClaim: "groups",
			ProfileJSON: map[string]interface{}{
				"email":  "new@thing.com",
				"groups": "singleton",
			},
			ExpectedError: nil,
			ExpectedSession: &sessions.SessionState{
				User:         "already",
				Email:        "already@populated.com",
				Groups:       []string{"singleton"},
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
		},
		"Missing Groups in both Claims and Profile URL": {
			ExistingSession: &sessions.SessionState{
				User:         "already",
				Email:        "already@populated.com",
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
			EmailClaim:  "email",
			GroupsClaim: "groups",
			ProfileJSON: map[string]interface{}{
				"email": "new@thing.com",
			},
			ExpectedError: nil,
			ExpectedSession: &sessions.SessionState{
				User:         "already",
				Email:        "already@populated.com",
				IDToken:      idToken,
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
			},
		},
	}
	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			jsonResp, err := json.Marshal(tc.ProfileJSON)
			assert.NoError(t, err)

			server, provider := newTestSetup(jsonResp)
			provider.ProfileURL, err = url.Parse(server.URL)
			assert.NoError(t, err)

			provider.EmailClaim = tc.EmailClaim
			provider.GroupsClaim = tc.GroupsClaim
			defer server.Close()

			err = provider.EnrichSession(context.Background(), tc.ExistingSession)
			assert.Equal(t, tc.ExpectedError, err)
			assert.Equal(t, *tc.ExpectedSession, *tc.ExistingSession)
		})
	}
}

func TestOIDCProviderRefreshSessionIfNeededWithoutIdToken(t *testing.T) {

	idToken, _ := newSignedTestIDToken(defaultIDToken)
	body, _ := json.Marshal(redeemTokenResponse{
		AccessToken:  accessToken,
		ExpiresIn:    10,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
	})

	server, provider := newTestSetup(body)
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

	refreshed, err := provider.RefreshSessionIfNeeded(context.Background(), existingSession)
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

	server, provider := newTestSetup(body)
	defer server.Close()

	existingSession := &sessions.SessionState{
		AccessToken:  "changeit",
		IDToken:      "changeit",
		CreatedAt:    nil,
		ExpiresOn:    nil,
		RefreshToken: refreshToken,
		Email:        "changeit",
		User:         "changeit",
	}
	refreshed, err := provider.RefreshSessionIfNeeded(context.Background(), existingSession)
	assert.Equal(t, nil, err)
	assert.Equal(t, refreshed, true)
	assert.Equal(t, defaultIDToken.Email, existingSession.Email)
	assert.Equal(t, defaultIDToken.Subject, existingSession.User)
	assert.Equal(t, accessToken, existingSession.AccessToken)
	assert.Equal(t, idToken, existingSession.IDToken)
	assert.Equal(t, refreshToken, existingSession.RefreshToken)
}

func TestOIDCProviderCreateSessionFromToken(t *testing.T) {
	const profileURLEmail = "janed@me.com"

	testCases := map[string]struct {
		IDToken        idTokenClaims
		GroupsClaim    string
		ExpectedUser   string
		ExpectedEmail  string
		ExpectedGroups interface{}
	}{
		"Default IDToken": {
			IDToken:        defaultIDToken,
			GroupsClaim:    "groups",
			ExpectedUser:   defaultIDToken.Subject,
			ExpectedEmail:  defaultIDToken.Email,
			ExpectedGroups: []string{"test:a", "test:b"},
		},
		"Minimal IDToken with no email claim": {
			IDToken:        minimalIDToken,
			GroupsClaim:    "groups",
			ExpectedUser:   minimalIDToken.Subject,
			ExpectedEmail:  minimalIDToken.Subject,
			ExpectedGroups: []string{},
		},
		"Custom Groups Claim": {
			IDToken:        defaultIDToken,
			GroupsClaim:    "other_groups",
			ExpectedUser:   defaultIDToken.Subject,
			ExpectedEmail:  defaultIDToken.Email,
			ExpectedGroups: []string{"test:c", "test:d"},
		},
		"Custom Groups Claim2": {
			IDToken:        customGroupClaimIDToken,
			GroupsClaim:    "groups",
			ExpectedUser:   customGroupClaimIDToken.Subject,
			ExpectedEmail:  customGroupClaimIDToken.Email,
			ExpectedGroups: []string{"{\"groupId\":\"Admin Group Id\",\"roles\":[\"Admin\"]}"},
		},
	}
	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			jsonResp := []byte(fmt.Sprintf(`{"email":"%s"}`, profileURLEmail))
			server, provider := newTestSetup(jsonResp)
			provider.GroupsClaim = tc.GroupsClaim
			defer server.Close()

			rawIDToken, err := newSignedTestIDToken(tc.IDToken)
			assert.NoError(t, err)

			ss, err := provider.CreateSessionFromToken(context.Background(), rawIDToken)
			assert.NoError(t, err)

			assert.Equal(t, tc.ExpectedUser, ss.User)
			assert.Equal(t, tc.ExpectedEmail, ss.Email)
			assert.Equal(t, rawIDToken, ss.IDToken)
			assert.Equal(t, rawIDToken, ss.AccessToken)
			assert.Equal(t, tc.ExpectedGroups, ss.Groups)
			assert.Equal(t, "", ss.RefreshToken)
		})
	}
}

func TestOIDCProvider_findVerifiedIDToken(t *testing.T) {

	server, provider := newTestSetup([]byte(""))

	defer server.Close()

	token := newOauth2Token()
	signedIDToken, _ := newSignedTestIDToken(defaultIDToken)
	tokenWithIDToken := token.WithExtra(map[string]interface{}{
		"id_token": signedIDToken,
	})

	verifiedIDToken, err := provider.findVerifiedIDToken(context.Background(), tokenWithIDToken)
	assert.Equal(t, true, err == nil)
	if verifiedIDToken == nil {
		t.Fatal("verifiedIDToken is nil")
	}
	assert.Equal(t, defaultIDToken.Issuer, verifiedIDToken.Issuer)
	assert.Equal(t, defaultIDToken.Subject, verifiedIDToken.Subject)

	// When the validation fails the response should be nil
	defaultIDToken.Id = "this-id-fails-validation"
	signedIDToken, _ = newSignedTestIDToken(defaultIDToken)
	tokenWithIDToken = token.WithExtra(map[string]interface{}{
		"id_token": signedIDToken,
	})

	verifiedIDToken, err = provider.findVerifiedIDToken(context.Background(), tokenWithIDToken)
	assert.Equal(t, errors.New("failed to verify signature: the validation failed for subject [123456789]"), err)
	assert.Equal(t, true, verifiedIDToken == nil)

	// When there is no id token in the oauth token
	verifiedIDToken, err = provider.findVerifiedIDToken(context.Background(), newOauth2Token())
	assert.Equal(t, nil, err)
	assert.Equal(t, true, verifiedIDToken == nil)
}
