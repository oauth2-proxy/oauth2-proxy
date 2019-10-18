package providers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/encryption"
	"github.com/pusher/oauth2_proxy/pkg/logger"
	"github.com/pusher/oauth2_proxy/pkg/requests"
	"golang.org/x/oauth2"
)

// DefaultProvider acting as a base for custom providers
type DefaultProvider struct {
	*ProviderData
	Redeemer             Redeemer
	ClaimExporter        ClaimExporter
	UserInfoFiller       UserInfoFiller
	Verifier             *oidc.IDTokenVerifier
	AllowUnverifiedEmail bool
}

// GenericClaims represents list of all available claims
type GenericClaims struct {
	Subject  string `json:"sub"`
	Email    string `json:"email"`
	Verified *bool  `json:"email_verified"`
}

func (p *DefaultProvider) getTemplate() interface{} {
	return &GenericClaims{}
}

func (p *DefaultProvider) normalize(claims interface{}) *GenericClaims {
	return claims.(*GenericClaims)

}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *DefaultProvider) Redeem(redirectURL, code string) (s *sessions.SessionState, err error) {
	ctx := context.Background()
	authConfig := p.Redeemer.getAuthFlowConfigWithRedirect(redirectURL)
	token, err := p.Redeemer.exchangeCodeForToken(ctx, authConfig, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %v", err)
	}
	idToken, err := p.Redeemer.verifyIDToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("IDtoken verification failed: %v", err)
	}
	s, err = p.Redeemer.createSessionState(idToken, token)
	if err != nil {
		return nil, fmt.Errorf("unable to update session: %v", err)
	}
	return
}

// RefreshSessionIfNeeded checks if the session has expired and uses the
// RefreshToken to fetch a new ID token if required
func (p *DefaultProvider) RefreshSessionIfNeeded(s *sessions.SessionState) (bool, error) {
	if s == nil || s.ExpiresOn.After(time.Now()) || s.RefreshToken == "" {
		return false, nil
	}

	origExpiration := s.ExpiresOn

	err := p.redeemRefreshToken(s)

	if err != nil {
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	fmt.Printf("refreshed id token %s (expired on %s)\n", s, origExpiration)
	return true, nil
}

func (p *DefaultProvider) redeemRefreshToken(s *sessions.SessionState) (err error) {
	ctx := context.Background()
	authConfig := p.Redeemer.getAuthFlowConfig()
	token, err := p.Redeemer.exchangeRefreshTokenForToken(ctx, authConfig, s.RefreshToken)
	if err != nil {
		return fmt.Errorf("failed to get token: %v", err)
	}
	idToken, err := p.Redeemer.verifyIDToken(ctx, token)
	if err != nil {
		return fmt.Errorf("IDtoken verification failed: %v", err)
	}
	newSession, err := p.Redeemer.createSessionState(idToken, token)
	if err != nil {
		return fmt.Errorf("unable to update session: %v", err)
	}
	logger.Printf("Current time: %s", time.Now())
	s.AccessToken = newSession.AccessToken
	s.IDToken = newSession.IDToken
	s.RefreshToken = newSession.RefreshToken
	s.CreatedAt = newSession.CreatedAt
	s.ExpiresOn = newSession.ExpiresOn
	s.Email = newSession.Email
	return
}
func (p *DefaultProvider) getAuthFlowConfig() (c *oauth2.Config) {

	c = &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
	}
	return
}

func (p *DefaultProvider) getAuthFlowConfigWithRedirect(redirectURL string) (c *oauth2.Config) {
	c = p.getAuthFlowConfig()
	c.RedirectURL = redirectURL
	return
}

func (p *DefaultProvider) exchangeCodeForToken(ctx context.Context, authConfig *oauth2.Config, code string) (token *oauth2.Token, err error) {
	token, err = authConfig.Exchange(ctx, code)
	return
}

func (p *DefaultProvider) exchangeRefreshTokenForToken(ctx context.Context, authConfig *oauth2.Config, refreshToken string) (token *oauth2.Token, err error) {
	t := &oauth2.Token{
		RefreshToken: refreshToken,
		Expiry:       time.Now().Add(-time.Hour),
	}
	token, err = authConfig.TokenSource(ctx, t).Token()
	return
}

func (p *DefaultProvider) verifyIDToken(ctx context.Context, token *oauth2.Token) (idToken *oidc.IDToken, err error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("token response did not contain an id_token")
	}

	// Parse and verify ID Token payload.
	idToken, err = p.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("could not verify id_token: %v", err)
	}
	return
}

func (p *DefaultProvider) extractClaims(idToken *oidc.IDToken) (*GenericClaims, error) {

	// Extract custom claims.
	claims := p.ClaimExporter.getTemplate()
	if err := idToken.Claims(claims); err != nil {
		return nil, err
	}
	return p.ClaimExporter.normalize(claims), nil
}

func (p *DefaultProvider) createSessionState(idToken *oidc.IDToken, token *oauth2.Token) (*sessions.SessionState, error) {
	claims, err := p.extractClaims(idToken)
	if err != nil {
		return nil, fmt.Errorf("failed to parse id_token claims: %v", err)
	}
	if claims.Email == "" {
		if claims.Email, err = p.UserInfoFiller.fillEmail(token); err != nil {
			return nil, fmt.Errorf("failed to obtain user email: %v", err)
		}
	}
	if !p.AllowUnverifiedEmail && claims.Verified != nil && !*claims.Verified {
		return nil, fmt.Errorf("email in id_token (%s) isn't verified", claims.Email)
	}
	rawIDToken, _ := token.Extra("id_token").(string)
	return &sessions.SessionState{
		AccessToken:  token.AccessToken,
		IDToken:      rawIDToken,
		RefreshToken: token.RefreshToken,
		CreatedAt:    time.Now(),
		ExpiresOn:    idToken.Expiry,
		Email:        claims.Email,
		User:         p.UserInfoFiller.fillUser(claims, token),
	}, nil
}

func (p *DefaultProvider) fillEmail(token *oauth2.Token) (string, error) {
	if p.ProfileURL.String() == "" {
		return "", fmt.Errorf("id_token did not contain an email")
	}

	// If the userinfo endpoint profileURL is defined, then there is a chance the userinfo
	// contents at the profileURL contains the email.
	// Make a query to the userinfo endpoint, and attempt to locate the email from there.

	req, err := http.NewRequest("GET", p.ProfileURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header = getAuthHeader(token.AccessToken)

	respJSON, err := requests.Request(req)
	if err != nil {
		return "", err
	}

	email, err := respJSON.Get("email").String()
	if err != nil {
		return "", fmt.Errorf("Neither id_token nor userinfo endpoint contained an email")
	}

	return email, nil
}

// GetLoginURL with typical oauth parameters
func (p *DefaultProvider) GetLoginURL(redirectURI, state string) string {
	var a url.URL
	a = *p.LoginURL
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("redirect_uri", redirectURI)
	params.Set("approval_prompt", p.ApprovalPrompt)
	params.Add("scope", p.Scope)
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "code")
	params.Add("state", state)
	a.RawQuery = params.Encode()
	return a.String()
}

func getAuthHeader(accessToken string) http.Header {
	header := make(http.Header)
	header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	return header
}

// CookieForSession serializes a session state for storage in a cookie
func (p *DefaultProvider) CookieForSession(s *sessions.SessionState, c *encryption.Cipher) (string, error) {
	return s.EncodeSessionState(c)
}

// SessionFromCookie deserializes a session from a cookie value
func (p *DefaultProvider) SessionFromCookie(v string, c *encryption.Cipher) (s *sessions.SessionState, err error) {
	return sessions.DecodeSessionState(v, c)
}

// GetEmailAddress returns the Account email address
func (p *DefaultProvider) GetEmailAddress(s *sessions.SessionState) (string, error) {
	return "", errors.New("not implemented")
}

// GetUserName returns the Account username
func (p *DefaultProvider) GetUserName(s *sessions.SessionState) (string, error) {
	return "", errors.New("not implemented")
}

// ValidateGroup validates that the provided email exists in the configured provider
// email group(s).
func (p *DefaultProvider) ValidateGroup(email string) bool {
	return true
}

// ValidateSessionState validates the AccessToken
func (p *DefaultProvider) ValidateSessionState(s *sessions.SessionState) bool {
	return validateToken(p, s.AccessToken, nil)
}
