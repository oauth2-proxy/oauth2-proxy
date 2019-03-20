package providers

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
)

type MyKeyData struct {
	PubKey  crypto.PublicKey
	PrivKey *rsa.PrivateKey
	PubJWK  jose.JSONWebKey
}

func newLoginGovServer(body []byte) (*url.URL, *httptest.Server) {
	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Write(body)
	}))
	u, _ := url.Parse(s.URL)
	return u, s
}

func newLoginGovProvider() (l *LoginGovProvider, serverKey *MyKeyData, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	serverKey = &MyKeyData{
		PubKey:  key.Public(),
		PrivKey: key,
		PubJWK: jose.JSONWebKey{
			Key:       key.Public(),
			KeyID:     "testkey",
			Algorithm: string(jose.RS256),
			Use:       "sig",
		},
	}

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
	p, _, err := newLoginGovProvider()
	assert.NotEqual(t, nil, p)
	assert.NoError(t, err)
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
	p, serverkey, err := newLoginGovProvider()
	assert.NotEqual(t, nil, p)
	assert.NoError(t, err)

	// Set up the redeem endpoint here
	type loginGovRedeemResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		IDToken     string `json:"id_token"`
	}
	expiresIn := int64(60)
	type MyCustomClaims struct {
		Acr           string `json:"acr"`
		Nonce         string `json:"nonce"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Birthdate     string `json:"birthdate"`
		AtHash        string `json:"at_hash"`
		CHash         string `json:"c_hash"`
		jwt.StandardClaims
	}
	claims := MyCustomClaims{
		"http://idmanagement.gov/ns/assurance/loa/1",
		"fakenonce",
		"timothy.spencer@gsa.gov",
		true,
		"",
		"",
		"",
		"",
		"",
		jwt.StandardClaims{
			Audience:  "Audience",
			ExpiresAt: time.Now().Unix() + expiresIn,
			Id:        "foo",
			IssuedAt:  time.Now().Unix(),
			Issuer:    "https://idp.int.login.gov",
			NotBefore: time.Now().Unix() - 1,
			Subject:   "b2d2d115-1d7e-4579-b9d6-f8e84f4f56ca",
		},
	}
	idtoken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedidtoken, err := idtoken.SignedString(serverkey.PrivKey)
	assert.NoError(t, err)
	body, err := json.Marshal(loginGovRedeemResponse{
		AccessToken: "a1234",
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		IDToken:     signedidtoken,
	})
	assert.NoError(t, err)
	var server *httptest.Server
	p.RedeemURL, server = newLoginGovServer(body)
	defer server.Close()

	// Set up the user endpoint here
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
	assert.NoError(t, err)
	var userserver *httptest.Server
	p.ProfileURL, userserver = newLoginGovServer(userbody)
	defer userserver.Close()

	// Set up the PubJWKURL endpoint here used to verify the JWT
	var pubkeys jose.JSONWebKeySet
	pubkeys.Keys = append(pubkeys.Keys, serverkey.PubJWK)
	pubjwkbody, err := json.Marshal(pubkeys)
	assert.NoError(t, err)
	var pubjwkserver *httptest.Server
	p.PubJWKURL, pubjwkserver = newLoginGovServer(pubjwkbody)
	defer pubjwkserver.Close()

	session, err := p.Redeem("http://redirect/", "code1234")
	assert.NoError(t, err)
	assert.NotEqual(t, session, nil)
	assert.Equal(t, "timothy.spencer@gsa.gov", session.Email)
	assert.Equal(t, "a1234", session.AccessToken)

	// The test ought to run in under 2 seconds.  If not, you may need to bump this up.
	assert.InDelta(t, session.ExpiresOn.Unix(), time.Now().Unix()+expiresIn, 2)
}

func TestLoginGovProviderBadNonce(t *testing.T) {
	p, serverkey, err := newLoginGovProvider()
	assert.NotEqual(t, nil, p)
	assert.NoError(t, err)

	// Set up the redeem endpoint here
	type loginGovRedeemResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
		IDToken     string `json:"id_token"`
	}
	expiresIn := int64(60)
	type MyCustomClaims struct {
		Acr           string `json:"acr"`
		Nonce         string `json:"nonce"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		GivenName     string `json:"given_name"`
		FamilyName    string `json:"family_name"`
		Birthdate     string `json:"birthdate"`
		AtHash        string `json:"at_hash"`
		CHash         string `json:"c_hash"`
		jwt.StandardClaims
	}
	claims := MyCustomClaims{
		"http://idmanagement.gov/ns/assurance/loa/1",
		"badfakenonce",
		"timothy.spencer@gsa.gov",
		true,
		"",
		"",
		"",
		"",
		"",
		jwt.StandardClaims{
			Audience:  "Audience",
			ExpiresAt: time.Now().Unix() + expiresIn,
			Id:        "foo",
			IssuedAt:  time.Now().Unix(),
			Issuer:    "https://idp.int.login.gov",
			NotBefore: time.Now().Unix() - 1,
			Subject:   "b2d2d115-1d7e-4579-b9d6-f8e84f4f56ca",
		},
	}
	idtoken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedidtoken, err := idtoken.SignedString(serverkey.PrivKey)
	assert.NoError(t, err)
	body, err := json.Marshal(loginGovRedeemResponse{
		AccessToken: "a1234",
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
		IDToken:     signedidtoken,
	})
	assert.NoError(t, err)
	var server *httptest.Server
	p.RedeemURL, server = newLoginGovServer(body)
	defer server.Close()

	// Set up the user endpoint here
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
	assert.NoError(t, err)
	var userserver *httptest.Server
	p.ProfileURL, userserver = newLoginGovServer(userbody)
	defer userserver.Close()

	// Set up the PubJWKURL endpoint here used to verify the JWT
	var pubkeys jose.JSONWebKeySet
	pubkeys.Keys = append(pubkeys.Keys, serverkey.PubJWK)
	pubjwkbody, err := json.Marshal(pubkeys)
	assert.NoError(t, err)
	var pubjwkserver *httptest.Server
	p.PubJWKURL, pubjwkserver = newLoginGovServer(pubjwkbody)
	defer pubjwkserver.Close()

	_, err = p.Redeem("http://redirect/", "code1234")

	// The "badfakenonce" in the idtoken above should cause this to error out
	assert.Error(t, err)
}
