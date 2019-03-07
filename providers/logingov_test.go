package providers

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func newLoginGovRedeemServer(body []byte) (*url.URL, *httptest.Server) {
	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Write(body)
	}))
	u, _ := url.Parse(s.URL)
	return u, s
}

func newLoginGovProvider() (l *LoginGovProvider, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}

	l = NewLoginGovProvider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""})
	l.JWTKey = privateKey
	l.Nonce = "fakenonce"
	return
}

func TestLoginGovProviderDefaults(t *testing.T) {
	p, err := newLoginGovProvider()
	assert.NotEqual(t, nil, p)
	assert.Equal(t, nil, err)
	assert.Equal(t, "login.gov", p.Data().ProviderName)
	assert.Equal(t, "https://secure.login.gov/openid_connect/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://secure.login.gov/api/openid_connect/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://secure.login.gov/api/openid_connect/userinfo",
		p.Data().ProfileURL.String())
	assert.Equal(t, "email openid", p.Data().Scope)
}

func TestLoginGovProviderOverrides(t *testing.T) {
	p := NewLoginGovProvider(
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
			Scope: "profile"})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "login.gov", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/oauth/auth",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://example.com/oauth/profile",
		p.Data().ProfileURL.String())
	assert.Equal(t, "profile", p.Data().Scope)
}

func TestLoginGovProviderSessionData(t *testing.T) {
	p, err := newLoginGovProvider()
	assert.NotEqual(t, nil, p)
	assert.Equal(t, nil, err)

	type loginGovRedeemResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		IDToken     string `json:"id_token"`
	}
	expiresIn := int64(10)
	body, err := json.Marshal(loginGovRedeemResponse{
		AccessToken: "a1234",
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		// This is a totally fake token.
		IDToken: base64.URLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + base64.URLEncoding.EncodeToString([]byte(`{"nonce": "fakenonce", "exp": 1234, "aud": "audience", "jti": "id", "iat": 1234, "iss": "issuer", "nbf": 1234, "sub": "subject"}`)) + ".aGVsbG8gd29ybGQK",
	})
	assert.Equal(t, nil, err)
	var server *httptest.Server
	p.RedeemURL, server = newLoginGovRedeemServer(body)
	defer server.Close()

	type loginGovUserResponse struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Subject       string `json:"sub"`
	}
	userbody, err := json.Marshal(loginGovUserResponse{
		Email:         "timothy.spencer@gsa.gov",
		EmailVerified: true,
		Subject:       "b2d2d115-1d7e-4579-b9d6-f8e84f4f56ca",
	})
	assert.Equal(t, nil, err)
	var userserver *httptest.Server
	p.ProfileURL, userserver = newLoginGovRedeemServer(userbody)
	defer userserver.Close()

	session, err := p.Redeem("http://redirect/", "code1234")
	assert.Equal(t, nil, err)
	assert.NotEqual(t, session, nil)
	assert.Equal(t, "timothy.spencer@gsa.gov", session.Email)
	assert.Equal(t, "a1234", session.AccessToken)

	// The test ought to run in under 2 seconds.  If not, you may need to bump this up.
	assert.InDelta(t, session.ExpiresOn.Unix(), time.Now().Unix()+expiresIn, 2)
}

func TestLoginGovProviderBadNonce(t *testing.T) {
	p, err := newLoginGovProvider()
	assert.NotEqual(t, nil, p)
	assert.Equal(t, nil, err)

	type loginGovRedeemResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		IDToken     string `json:"id_token"`
	}
	expiresIn := int64(10)
	body, err := json.Marshal(loginGovRedeemResponse{
		AccessToken: "a1234",
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		// This is a totally fake token.
		IDToken: base64.URLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) + "." + base64.URLEncoding.EncodeToString([]byte(`{"nonce": "badfakenonce", "exp": 1234, "aud": "audience", "jti": "id", "iat": 1234, "iss": "issuer", "nbf": 1234, "sub": "subject"}`)) + ".aGVsbG8gd29ybGQK",
	})
	assert.Equal(t, nil, err)
	var server *httptest.Server
	p.RedeemURL, server = newLoginGovRedeemServer(body)
	defer server.Close()

	type loginGovUserResponse struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Subject       string `json:"sub"`
	}
	userbody, err := json.Marshal(loginGovUserResponse{
		Email:         "timothy.spencer@gsa.gov",
		EmailVerified: true,
		Subject:       "b2d2d115-1d7e-4579-b9d6-f8e84f4f56ca",
	})
	assert.Equal(t, nil, err)
	var userserver *httptest.Server
	p.ProfileURL, userserver = newLoginGovRedeemServer(userbody)
	defer userserver.Close()

	_, err = p.Redeem("http://redirect/", "code1234")

	// The "badfakenonce" in the idtoken above should cause this to error out
	assert.NotEqual(t, nil, err)
}
