package providers

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"gopkg.in/square/go-jose.v2"
)

// LoginGovProvider represents an OIDC based Identity Provider
type LoginGovProvider struct {
	*ProviderData

	// TODO (@timothy-spencer): Ideally, the nonce would be in the session state, but the session state
	// is created only upon code redemption, not during the auth, when this must be supplied.
	Nonce     string
	AcrValues string
	JWTKey    *rsa.PrivateKey
	PubJWKURL *url.URL
}

// For generating a nonce
var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// NewLoginGovProvider initiates a new LoginGovProvider
func NewLoginGovProvider(p *ProviderData) *LoginGovProvider {
	p.ProviderName = "login.gov"

	if p.LoginURL == nil || p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   "secure.login.gov",
			Path:   "/openid_connect/authorize",
		}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   "secure.login.gov",
			Path:   "/api/openid_connect/token",
		}
	}
	if p.ProfileURL == nil || p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{
			Scheme: "https",
			Host:   "secure.login.gov",
			Path:   "/api/openid_connect/userinfo",
		}
	}
	if p.Scope == "" {
		p.Scope = "email openid"
	}

	return &LoginGovProvider{
		ProviderData: p,
		Nonce:        randSeq(32),
	}
}

type loginGovCustomClaims struct {
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

// checkNonce checks the nonce in the id_token
func checkNonce(idToken string, p *LoginGovProvider) (err error) {
	token, err := jwt.ParseWithClaims(idToken, &loginGovCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		resp, myerr := http.Get(p.PubJWKURL.String())
		if myerr != nil {
			return nil, myerr
		}
		if resp.StatusCode != 200 {
			myerr = fmt.Errorf("got %d from %q", resp.StatusCode, p.PubJWKURL.String())
			return nil, myerr
		}
		body, myerr := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if myerr != nil {
			return nil, myerr
		}

		var pubkeys jose.JSONWebKeySet
		myerr = json.Unmarshal(body, &pubkeys)
		if myerr != nil {
			return nil, myerr
		}
		pubkey := pubkeys.Keys[0]

		return pubkey.Key, nil
	})
	if err != nil {
		return
	}

	claims := token.Claims.(*loginGovCustomClaims)
	if claims.Nonce != p.Nonce {
		err = fmt.Errorf("nonce validation failed")
		return
	}
	return
}

func emailFromUserInfo(accessToken string, userInfoEndpoint string) (email string, err error) {
	// query the user info endpoint for user attributes
	var req *http.Request
	req, err = http.NewRequest("GET", userInfoEndpoint, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, userInfoEndpoint, body)
		return
	}

	// parse the user attributes from the data we got and make sure that
	// the email address has been validated.
	var emailData struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	err = json.Unmarshal(body, &emailData)
	if err != nil {
		return
	}
	if emailData.Email == "" {
		err = fmt.Errorf("missing email")
		return
	}
	email = emailData.Email
	if !emailData.EmailVerified {
		err = fmt.Errorf("email %s not listed as verified", email)
		return
	}
	return
}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *LoginGovProvider) Redeem(redirectURL, code string) (s *sessions.SessionState, err error) {
	if code == "" {
		err = errors.New("missing code")
		return
	}

	claims := &jwt.StandardClaims{
		Issuer:    p.ClientID,
		Subject:   p.ClientID,
		Audience:  p.RedeemURL.String(),
		ExpiresAt: int64(time.Now().Add(time.Duration(5 * time.Minute)).Unix()),
		Id:        randSeq(32),
	}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), claims)
	ss, err := token.SignedString(p.JWTKey)
	if err != nil {
		return
	}

	params := url.Values{}
	params.Add("client_assertion", ss)
	params.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")

	var req *http.Request
	req, err = http.NewRequest("POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var resp *http.Response
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
		return
	}

	// Get the token from the body that we got from the token endpoint.
	var jsonResponse struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	err = json.Unmarshal(body, &jsonResponse)
	if err != nil {
		return
	}

	// check nonce here
	err = checkNonce(jsonResponse.IDToken, p)
	if err != nil {
		return
	}

	// Get the email address
	var email string
	email, err = emailFromUserInfo(jsonResponse.AccessToken, p.ProfileURL.String())
	if err != nil {
		return
	}

	// Store the data that we found in the session state
	s = &sessions.SessionState{
		AccessToken: jsonResponse.AccessToken,
		IDToken:     jsonResponse.IDToken,
		CreatedAt:   time.Now(),
		ExpiresOn:   time.Now().Add(time.Duration(jsonResponse.ExpiresIn) * time.Second).Truncate(time.Second),
		Email:       email,
	}
	return
}

// GetLoginURL overrides GetLoginURL to add login.gov parameters
func (p *LoginGovProvider) GetLoginURL(redirectURI, state string) string {
	var a url.URL
	a = *p.LoginURL
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("redirect_uri", redirectURI)
	params.Set("approval_prompt", p.ApprovalPrompt)
	params.Add("scope", p.Scope)
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "code")
	params.Add("state", state)
	params.Add("acr_values", p.AcrValues)
	params.Add("nonce", p.Nonce)
	a.RawQuery = params.Encode()
	return a.String()
}
