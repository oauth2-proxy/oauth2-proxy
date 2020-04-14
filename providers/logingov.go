package providers

import (
	"bytes"
	"context"
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
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"gopkg.in/square/go-jose.v2"
)

// LoginGovProvider represents an OIDC based Identity Provider
type LoginGovProvider struct {
	*ProviderData

	// TODO (@timothy-spencer): Ideally, the nonce would be in the session state, but the session state
	// is created only upon code redemption, not during the auth, when this must be supplied.
	Nonce     string
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
func checkNonce(ctx context.Context, idToken string, p *LoginGovProvider) error {
	token, err := jwt.ParseWithClaims(idToken, &loginGovCustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.PubJWKURL.String(), nil)
		if err != nil {
			return nil, err
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("got %d from %q", resp.StatusCode, p.PubJWKURL.String())
		}
		body, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}

		var pubkeys jose.JSONWebKeySet
		err = json.Unmarshal(body, &pubkeys)
		if err != nil {
			return nil, err
		}
		if len(pubkeys.Keys) == 0 {
			return nil, fmt.Errorf("no keys in jwt: pubkeys=%v", pubkeys)
		}
		pubkey := pubkeys.Keys[0]

		return pubkey.Key, nil
	})
	if err != nil {
		return err
	}

	claims := token.Claims.(*loginGovCustomClaims)
	if claims.Nonce != p.Nonce {
		return fmt.Errorf("nonce validation failed")
	}
	return nil
}

func emailFromUserInfo(ctx context.Context, accessToken string, userInfoEndpoint string) (string, error) {
	// query the user info endpoint for user attributes
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoEndpoint, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("got %d from %q %s", resp.StatusCode, userInfoEndpoint, body)
	}

	// parse the user attributes from the data we got and make sure that
	// the email address has been validated.
	var emailData struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	err = json.Unmarshal(body, &emailData)
	if err != nil {
		return "", err
	}
	if emailData.Email == "" {
		return "", fmt.Errorf("missing email")
	}
	email := emailData.Email
	if !emailData.EmailVerified {
		return "", fmt.Errorf("email %s not listed as verified", email)
	}
	return email, nil
}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *LoginGovProvider) Redeem(ctx context.Context, redirectURL, code string) (*sessions.SessionState, error) {
	if code == "" {
		return nil, errors.New("missing code")
	}

	claims := &jwt.StandardClaims{
		Issuer:    p.ClientID,
		Subject:   p.ClientID,
		Audience:  p.RedeemURL.String(),
		ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		Id:        randSeq(32),
	}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), claims)
	ss, err := token.SignedString(p.JWTKey)
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	params.Add("client_assertion", ss)
	params.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return nil, err
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
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
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
		return nil, err
	}

	// check nonce here
	err = checkNonce(ctx, jsonResponse.IDToken, p)
	if err != nil {
		return nil, err
	}

	// Get the email address
	email, err := emailFromUserInfo(ctx, jsonResponse.AccessToken, p.ProfileURL.String())
	if err != nil {
		return nil, err
	}

	// Store the data that we found in the session state
	s := &sessions.SessionState{
		AccessToken: jsonResponse.AccessToken,
		IDToken:     jsonResponse.IDToken,
		CreatedAt:   time.Now(),
		ExpiresOn:   time.Now().Add(time.Duration(jsonResponse.ExpiresIn) * time.Second).Truncate(time.Second),
		Email:       email,
	}
	return s, nil
}

// GetLoginURL overrides GetLoginURL to add login.gov parameters
func (p *LoginGovProvider) GetLoginURL(redirectURI, state string) string {
	a := *p.LoginURL
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("redirect_uri", redirectURI)
	params.Set("approval_prompt", p.ApprovalPrompt)
	params.Add("scope", p.Scope)
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "code")
	params.Add("state", state)
	acr := p.AcrValues
	if acr == "" {
		acr = "http://idmanagement.gov/ns/assurance/loa/1"
	}
	params.Add("acr_values", acr)
	params.Add("nonce", p.Nonce)
	a.RawQuery = params.Encode()
	return a.String()
}
