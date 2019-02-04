package providers

import (
	"context"
	"fmt"
	"net/url"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jwt"

	oidc "github.com/coreos/go-oidc"
	"math/rand"
)

// LoginGovProvider represents an OIDC based Identity Provider
type LoginGovProvider struct {
	*ProviderData

	Nonce     string
	AcrValues string
	JWTKey    []byte
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

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *LoginGovProvider) Redeem(redirectURL, code string) (s *SessionState, err error) {
	ctx := context.Background()
	c := jwt.Config{
		Email:      p.ClientID,
		PrivateKey: p.JWTKey,
		TokenURL:   p.RedeemURL.String(),
	}
	token, err := c.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %v", err)
	}
	s, err = p.createSessionState(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("unable to update session: %v", err)
	}
	return
}

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
