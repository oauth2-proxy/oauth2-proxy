package providers

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/golang-jwt/jwt/v5"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
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

var _ Provider = (*LoginGovProvider)(nil)

// For generating a nonce
var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		maxInt := big.NewInt(int64(len(letters)))
		bigN, err := rand.Int(rand.Reader, maxInt)
		if err != nil {
			// This should never happen
			panic(err)
		}
		b[i] = letters[bigN.Int64()]
	}
	return string(b)
}

const (
	loginGovProviderName = "login.gov"
	loginGovDefaultScope = "email openid"
)

var (
	// Default Login URL for LoginGov.
	// Pre-parsed URL of https://secure.login.gov/openid_connect/authorize.
	loginGovDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "secure.login.gov",
		Path:   "/openid_connect/authorize",
	}

	// Default Redeem URL for LoginGov.
	// Pre-parsed URL of https://secure.login.gov/api/openid_connect/token.
	loginGovDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "secure.login.gov",
		Path:   "/api/openid_connect/token",
	}

	// Default Profile URL for LoginGov.
	// Pre-parsed URL of https://graph.loginGov.com/v2.5/me.
	loginGovDefaultProfileURL = &url.URL{
		Scheme: "https",
		Host:   "secure.login.gov",
		Path:   "/api/openid_connect/userinfo",
	}
)

// NewLoginGovProvider initiates a new LoginGovProvider
func NewLoginGovProvider(p *ProviderData, opts options.LoginGovOptions) (*LoginGovProvider, error) {
	p.setProviderDefaults(providerDefaults{
		name:        loginGovProviderName,
		loginURL:    loginGovDefaultLoginURL,
		redeemURL:   loginGovDefaultRedeemURL,
		profileURL:  loginGovDefaultProfileURL,
		validateURL: loginGovDefaultProfileURL,
		scope:       loginGovDefaultScope,
	})
	provider := &LoginGovProvider{
		ProviderData: p,
		Nonce:        randSeq(32),
	}

	if err := provider.configure(opts); err != nil {
		return nil, fmt.Errorf("could not configure login.gov provider: %v", err)
	}
	return provider, nil
}

func (p *LoginGovProvider) configure(opts options.LoginGovOptions) error {
	pubJWKURL, err := url.Parse(opts.PubJWKURL)
	if err != nil {
		return fmt.Errorf("could not parse Public JWK URL: %v", err)
	}
	p.PubJWKURL = pubJWKURL

	// JWT key can be supplied via env variable or file in the filesystem, but not both.
	switch {
	case opts.JWTKey != "" && opts.JWTKeyFile != "":
		return errors.New("cannot set both jwt-key and jwt-key-file options")
	case opts.JWTKey == "" && opts.JWTKeyFile == "":
		return errors.New("login.gov provider requires a private key for signing JWTs")
	case opts.JWTKey != "":
		// The JWT Key is in the commandline argument
		signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(opts.JWTKey))
		if err != nil {
			return fmt.Errorf("could not parse RSA Private Key PEM: %v", err)
		}
		p.JWTKey = signKey
	case opts.JWTKeyFile != "":
		// The JWT key is in the filesystem
		keyData, err := os.ReadFile(opts.JWTKeyFile)
		if err != nil {
			return fmt.Errorf("could not read key file: %v", opts.JWTKeyFile)
		}
		signKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
		if err != nil {
			return fmt.Errorf("could not parse private key from PEM file: %v", opts.JWTKeyFile)
		}
		p.JWTKey = signKey
	}
	return nil
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
	jwt.RegisteredClaims
}

// checkNonce checks the nonce in the id_token
func checkNonce(idToken string, p *LoginGovProvider) (err error) {
	token, err := jwt.ParseWithClaims(idToken, &loginGovCustomClaims{}, func(_ *jwt.Token) (interface{}, error) {
		var pubkeys jose.JSONWebKeySet
		rerr := requests.New(p.PubJWKURL.String()).Do().UnmarshalInto(&pubkeys)
		if rerr != nil {
			return nil, rerr
		}
		return pubkeys.Keys[0].Key, nil
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

func emailFromUserInfo(ctx context.Context, accessToken string, userInfoEndpoint string) (string, error) {
	// parse the user attributes from the data we got and make sure that
	// the email address has been validated.
	var emailData struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}

	// query the user info endpoint for user attributes
	err := requests.New(userInfoEndpoint).
		WithContext(ctx).
		SetHeader("Authorization", tokenTypeBearer+" "+accessToken).
		Do().
		UnmarshalInto(&emailData)
	if err != nil {
		return "", err
	}

	email := emailData.Email
	if email == "" {
		return "", fmt.Errorf("missing email")
	}

	if !emailData.EmailVerified {
		return "", fmt.Errorf("email %s not listed as verified", email)
	}

	return email, nil
}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *LoginGovProvider) Redeem(ctx context.Context, _, code, codeVerifier string) (*sessions.SessionState, error) {
	if code == "" {
		return nil, ErrMissingCode
	}

	claims := &jwt.RegisteredClaims{
		Issuer:    p.ClientID,
		Subject:   p.ClientID,
		Audience:  jwt.ClaimStrings{p.RedeemURL.String()},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
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
	if codeVerifier != "" {
		params.Add("code_verifier", codeVerifier)
	}

	// Get the token from the body that we got from the token endpoint.
	var jsonResponse struct {
		AccessToken string `json:"access_token"`
		IDToken     string `json:"id_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	err = requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do().
		UnmarshalInto(&jsonResponse)
	if err != nil {
		return nil, err
	}

	// check nonce here
	err = checkNonce(jsonResponse.IDToken, p)
	if err != nil {
		return nil, err
	}

	// Get the email address
	var email string
	email, err = emailFromUserInfo(ctx, jsonResponse.AccessToken, p.ProfileURL.String())
	if err != nil {
		return nil, err
	}

	session := &sessions.SessionState{
		AccessToken: jsonResponse.AccessToken,
		IDToken:     jsonResponse.IDToken,
		Email:       email,
	}

	session.CreatedAtNow()
	session.ExpiresIn(time.Duration(jsonResponse.ExpiresIn) * time.Second)

	return session, nil
}

// GetLoginURL overrides GetLoginURL to add login.gov parameters
func (p *LoginGovProvider) GetLoginURL(redirectURI, state, _ string, extraParams url.Values) string {
	if len(extraParams["acr_values"]) == 0 {
		acr := "http://idmanagement.gov/ns/assurance/loa/1"
		extraParams.Add("acr_values", acr)
	}
	extraParams.Add("nonce", p.Nonce)
	a := makeLoginURL(p.ProviderData, redirectURI, state, extraParams)
	return a.String()
}

// ValidateSession validates the AccessToken
func (p *LoginGovProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
}
