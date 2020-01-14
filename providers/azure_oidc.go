package providers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/logger"
	"github.com/pusher/oauth2_proxy/pkg/requests"
	"golang.org/x/oauth2"
)

type AzureOIDCProvider struct {
	*OIDCProvider
	PermittedGroups []string
	ExemptedEmails  []string
}

type AzureOIDCClaims struct {
	*OIDCClaims
	Groups            []string `json:"groups"`
	PreferredUsername string   `json:"preferred_username"`
}

// NewAzureOIDCProvider initiates a new AzureOIDCProvider
func NewAzureOIDCProvider(p *ProviderData) *AzureOIDCProvider {
	provider := AzureOIDCProvider{
		OIDCProvider: NewOIDCProvider(p),
	}
	provider.ProviderName = "Azure OpenID Connect"
	if p.Scope == "" {
		provider.Scope = "openid email profile"
	}

	if provider.ProfileURL == nil || provider.ProfileURL.String() == "" {
		provider.ProfileURL = &url.URL{
			Scheme: "https",
			Host:   "graph.microsoft.com",
			Path:   "/v1.0/me",
		}
	}

	return &provider
}

func (p *AzureOIDCProvider) GetLoginURL(redirectURI, state string) string {
	var a url.URL
	a = *p.LoginURL
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "id_token code")
	params.Set("redirect_uri", redirectURI)
	params.Set("response_mode", "form_post")
	params.Add("scope", p.Scope)
	params.Add("state", state)
	params.Set("prompt", p.ApprovalPrompt)
	params.Set("nonce", randSeq(32))
	a.RawQuery = params.Encode()
	return a.String()
}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *AzureOIDCProvider) Redeem(redirectURL, code string) (s *sessions.SessionState, err error) {
	ctx := context.Background()
	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
		RedirectURL: redirectURL,
		Scopes:      strings.Split(p.Scope, " "),
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

func (p *AzureOIDCProvider) RefreshSessionIfNeeded(s *sessions.SessionState) (bool, error) {
	return p.OIDCProvider.RefreshSessionIfNeeded(s)
}

func (p *AzureOIDCProvider) redeemRefreshToken(s *sessions.SessionState) (err error) {
	return p.OIDCProvider.redeemRefreshToken(s)
}

func (p *AzureOIDCProvider) createSessionState(ctx context.Context, token *oauth2.Token) (*sessions.SessionState, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("token response did not contain an id_token")
	}

	// Parse and verify ID Token payload.
	idToken, err := p.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("could not verify id_token: %v", err)
	}

	// Extract custom claims.
	var claims AzureOIDCClaims

	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse id_token claims: %v", err)
	}

	if claims.Email == "" {
		if p.ProfileURL.String() == "" {
			return nil, fmt.Errorf("id_token did not contain an email")
		}

		// If the userinfo endpoint profileURL is defined, then there is a chance the userinfo
		// contents at the profileURL contains the email.
		// Make a query to the userinfo endpoint, and attempt to locate the email from there.

		req, err := http.NewRequest("GET", p.ProfileURL.String(), nil)
		defer req.Body.Close()
		if err != nil {
			return nil, err
		}
		req.Header = getOIDCHeader(token.AccessToken)

		respJSON, err := requests.Request(req)
		if err != nil {
			return nil, err
		}

		email, err := respJSON.Get("email").String()
		if err != nil {
			return nil, fmt.Errorf("Neither id_token nor userinfo endpoint contained an email")
		}

		claims.Email = email
	}
	if !p.AllowUnverifiedEmail && claims.Verified != nil && !*claims.Verified {
		return nil, fmt.Errorf("email in id_token (%s) isn't verified", claims.Email)
	}

	return &sessions.SessionState{
		AccessToken:  token.AccessToken,
		IDToken:      rawIDToken,
		RefreshToken: token.RefreshToken,
		CreatedAt:    time.Now(),
		ExpiresOn:    idToken.Expiry,
		Email:        claims.Email,
		User:         claims.PreferredUsername,
	}, nil
}
func (p *AzureOIDCProvider) ValidateSessionState(s *sessions.SessionState) bool {
	return p.OIDCProvider.ValidateSessionState(s)
}

func (p *AzureOIDCProvider) SetGroupRestriction(groups []string) {
	p.PermittedGroups = groups
}

func (p *AzureOIDCProvider) SetGroupExemptions(exemptedEmails []string) {
	p.ExemptedEmails = exemptedEmails
}

func (p *AzureOIDCProvider) ValidateGroup(session *sessions.SessionState) bool {
	// configuration doesn't restrict access via groups
	if len(p.PermittedGroups) == 0 {
		return true
	}
	for _, exemptedEmail := range p.ExemptedEmails {
		if session.Email == exemptedEmail {
			return true
		}
	}

	if session.IDToken == "" {
		logger.Printf("missing ID token. cannot validate session")
		return false
	}

	var claims AzureOIDCClaims
	err := getClaimFromToken(session.IDToken, &claims)
	if err != nil {
		logger.Printf("error: failed to parse IDToken, %s", err)
		return false
	}
	for _, tokenGroup := range claims.Groups {
		for _, permittedGroup := range p.PermittedGroups {
			if tokenGroup == permittedGroup {
				return true
			}
		}
	}

	return false
}
