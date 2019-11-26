package providers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/oauth2"

	"github.com/bmizerany/assert"
	"github.com/coreos/go-oidc"
	"github.com/dgrijalva/jwt-go"
	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"

	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

const accessToken = "access_token"
const refreshToken = "refresh_token"
const clientID = "https://test.myapp.com"
const secret = "secret"

// https://openid.net/specs/openid-connect-core-1_0.html#Claims
type IDTokenClaims struct {
	Subject  string `json:"sub"`
	Email    string `json:"email"`
	Verified *bool  `json:"email_verified"`
	jwt.StandardClaims
}
type RedeemResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
	IDToken      string `json:"id_token,omitempty"`
}

func newIDToken(verified *bool) *IDTokenClaims {
	return &IDTokenClaims{
		"subject-id",
		"janed@me.com",
		verified,
		jwt.StandardClaims{
			Audience:  "https://test.myapp.com",
			ExpiresAt: time.Now().Add(time.Hour).Unix(),
			Id:        "id-some-id",
			IssuedAt:  time.Now().Unix(),
			Issuer:    "https://issuer.example.com",
			NotBefore: 0,
			Subject:   "123456789",
		},
	}
}

var verified = true
var unverified = false
var TestIDToken = newIDToken(&verified)

type NoOpKeySet struct{}

func (NoOpKeySet) VerifySignature(ctx context.Context, jwt string) (payload []byte, err error) {
	payloadPart := strings.Split(jwt, ".")[1]
	return base64.RawURLEncoding.DecodeString(payloadPart)
}

func newOIDCProvider(serverURL *url.URL) *OIDCProvider {
	return &OIDCProvider{
		ProviderData: &ProviderData{
			ProviderName: "oidc",
			ClientID:     clientID,
			ClientSecret: secret,
			RedeemURL: &url.URL{
				Scheme: serverURL.Scheme,
				Host:   serverURL.Host,
				Path:   "/login/oauth/access_token"},
			ProfileURL: &url.URL{
				Scheme: serverURL.Scheme,
				Host:   serverURL.Host,
				Path:   "/profile"},
			Scope: "openid profile offline_access"},
		Verifier: oidc.NewVerifier(
			"https://issuer.example.com",
			NoOpKeySet{},
			&oidc.Config{ClientID: clientID},
		),
	}
}

func newOIDCServer(body []byte) (*url.URL, *httptest.Server) {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Add("content-type", "application/json")
		rw.Write(body)
	}))
	url, _ := url.Parse(server.URL)
	return url, server
}

func createRawIDToken(token *IDTokenClaims) (string, error) {

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	standardClaims := jwt.NewWithClaims(jwt.SigningMethodRS256, token)
	return standardClaims.SignedString(key)
}

func createVerifiedIDToken(provider *OIDCProvider, rawIDToken string) (*oidc.IDToken, error) {
	ctx := context.Background()
	return provider.Verifier.Verify(ctx, rawIDToken)
}

func createOAuth2Token(rawIDToken string) (*oauth2.Token, error) {
	token := oauth2.Token{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		Expiry:       time.Now().Add(time.Minute),
	}

	tokenWithID := token.WithExtra(map[string]interface{}{
		"id_token": rawIDToken,
	})

	return tokenWithID, nil
}

func Test_createSessionStateErrorsOnUnvalidatedEmail(t *testing.T) {

	var server *httptest.Server
	redeemURL, server := newOIDCServer(nil)
	provider := newOIDCProvider(redeemURL)
	defer server.Close()

	rawIDToken, err := createRawIDToken(newIDToken(&unverified))
	assert.Equal(t, nil, err)

	tokenWithID, err := createOAuth2Token(rawIDToken)
	assert.Equal(t, nil, err)

	ctx := context.Background()
	verifiedIDToken, err := provider.Verifier.Verify(ctx, rawIDToken)
	assert.Equal(t, nil, err)

	provider.AllowUnverifiedEmail = false
	_, err = provider.createSessionState(tokenWithID, verifiedIDToken)
	assert.Equal(t, errors.New("email in id_token (janed@me.com) isn't verified"), err)
}

func TestOIDCProviderRedeem(t *testing.T) {

	rawIDToken, err := createRawIDToken(TestIDToken)
	assert.Equal(t, nil, err)

	body, err := json.Marshal(RedeemResponse{
		AccessToken:  accessToken,
		ExpiresIn:    10,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		IDToken:      rawIDToken,
	})
	assert.Equal(t, nil, err)

	var server *httptest.Server
	redeemURL, server := newOIDCServer(body)
	provider := newOIDCProvider(redeemURL)
	defer server.Close()

	session, err := provider.Redeem(provider.RedeemURL.String(), "code1234")
	assert.Equal(t, nil, err)
	assert.Equal(t, TestIDToken.Email, session.Email)
	assert.Equal(t, accessToken, session.AccessToken)
	assert.Equal(t, rawIDToken, session.IDToken)
	assert.Equal(t, refreshToken, session.RefreshToken)
	assert.Equal(t, TestIDToken.Subject, session.User)
}

func TestOIDCProviderRefreshSessionIfNeededWithoutIdToken(t *testing.T) {

	rawIDToken, err := createRawIDToken(TestIDToken)
	assert.Equal(t, nil, err)

	body, err := json.Marshal(RedeemResponse{
		AccessToken:  accessToken,
		ExpiresIn:    10,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
	})
	assert.Equal(t, nil, err)

	var server *httptest.Server
	redeemURL, server := newOIDCServer(body)
	provider := newOIDCProvider(redeemURL)
	defer server.Close()

	existingSession := &sessions.SessionState{
		AccessToken:  "changeit",
		IDToken:      rawIDToken,
		CreatedAt:    time.Time{},
		ExpiresOn:    time.Time{},
		RefreshToken: refreshToken,
		Email:        "janedoe@example.com",
		User:         "123456789",
	}
	refreshed, err := provider.RefreshSessionIfNeeded(existingSession)
	assert.Equal(t, nil, err)
	assert.Equal(t, refreshed, true)
	assert.Equal(t, "janedoe@example.com", existingSession.Email)
	assert.Equal(t, accessToken, existingSession.AccessToken)
	assert.Equal(t, rawIDToken, existingSession.IDToken)
	assert.Equal(t, refreshToken, existingSession.RefreshToken)
	assert.Equal(t, "123456789", existingSession.User)
}

func TestOIDCProviderRefreshSessionIfNeededWithIdToken(t *testing.T) {

	rawIDToken, err := createRawIDToken(TestIDToken)
	assert.Equal(t, nil, err)

	body, err := json.Marshal(RedeemResponse{
		AccessToken:  accessToken,
		ExpiresIn:    10,
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		IDToken:      rawIDToken,
	})
	assert.Equal(t, nil, err)

	var server *httptest.Server
	redeemURL, server := newOIDCServer(body)
	provider := newOIDCProvider(redeemURL)
	defer server.Close()

	existingSession := &sessions.SessionState{
		AccessToken:  "changeit",
		IDToken:      "changeit",
		CreatedAt:    time.Time{},
		ExpiresOn:    time.Time{},
		RefreshToken: refreshToken,
		Email:        "changeit",
		User:         "changeit",
	}
	refreshed, err := provider.RefreshSessionIfNeeded(existingSession)
	assert.Equal(t, nil, err)
	assert.Equal(t, true, refreshed)
	assert.Equal(t, TestIDToken.Email, existingSession.Email)
	assert.Equal(t, accessToken, existingSession.AccessToken)
	assert.Equal(t, rawIDToken, existingSession.IDToken)
	assert.Equal(t, refreshToken, existingSession.RefreshToken)
	assert.Equal(t, TestIDToken.Subject, existingSession.User)
}

func TestOIDCProvider_findClaimsFromIDToken(t *testing.T) {
	redeemURL, _ := newOIDCServer(nil)
	provider := newOIDCProvider(redeemURL)

	rawIDToken, err := createRawIDToken(TestIDToken)
	assert.Equal(t, nil, err)

	idToken, err := createVerifiedIDToken(provider, rawIDToken)
	assert.Equal(t, nil, err)

	foundIDToken, _ := findClaimsFromIDToken(idToken, accessToken, provider.ProfileURL.String())
	assert.Equal(t, TestIDToken.Subject, foundIDToken.Subject)
	assert.Equal(t, TestIDToken.Email, foundIDToken.Email)
	assert.Equal(t, &verified, foundIDToken.Verified)
}

func TestOIDCProvider_findVerifiedIdToken(t *testing.T) {

	ctx := context.Background()
	someURL, _ := url.Parse("http://test.foo.com")
	provider := newOIDCProvider(someURL)

	rawIDToken, err := createRawIDToken(newIDToken(&verified))
	assert.Equal(t, nil, err)

	tokenWithID, err := createOAuth2Token(rawIDToken)
	assert.Equal(t, nil, err)

	token, err := createVerifiedIDToken(provider, rawIDToken)
	assert.Equal(t, nil, err)

	foundIDToken, err := provider.findVerifiedIDToken(ctx, tokenWithID)
	assert.Equal(t, nil, err)
	assert.Equal(t, false, foundIDToken == nil)
	assert.Equal(t, token.Subject, foundIDToken.Subject)
	assert.Equal(t, token.Expiry.Unix(), foundIDToken.Expiry.Unix())
	assert.Equal(t, token.Issuer, foundIDToken.Issuer)
	assert.Equal(t, token.IssuedAt.Unix(), foundIDToken.IssuedAt.Unix())
}

func TestOIDCProvider_extractIDToken(t *testing.T) {

	someURL, _ := url.Parse("http://test.foo.com")
	provider := newOIDCProvider(someURL)

	verifierFn := func(rawIdToken string) (*oidc.IDToken, error) {
		switch {
		case rawIdToken == "some-token":
			return new(oidc.IDToken), nil
		case rawIdToken == "error":
			return nil, fmt.Errorf("kerblam")
		default:
			return nil, nil
		}
	}

	findTokenFn := func(in string) func() (string, bool) {
		return func() (string, bool) {
			return in, len(in) > 0
		}
	}

	token, err := provider.extractIDToken(findTokenFn("some-token"), verifierFn)
	assert.Equal(t, new(oidc.IDToken), token)
	assert.Equal(t, nil, err)

	token, err = provider.extractIDToken(findTokenFn("error"), verifierFn)
	assert.Equal(t, true, token == nil)
	assert.Equal(t, fmt.Errorf("kerblam"), err)

	token, err = provider.extractIDToken(findTokenFn(""), verifierFn)
	assert.Equal(t, true, token == nil)
	assert.Equal(t, nil, err)
}
