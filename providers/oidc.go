package providers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/requests"
)

const emailClaim = "email"

// OIDCProvider represents an OIDC based Identity Provider
type OIDCProvider struct {
	*ProviderData

	Verifier             *oidc.IDTokenVerifier
	AllowUnverifiedEmail bool
	UserIDClaim          string
}

// NewOIDCProvider initiates a new OIDCProvider
func NewOIDCProvider(p *ProviderData) *OIDCProvider {
	p.ProviderName = "OpenID Connect"
	return &OIDCProvider{ProviderData: p}
}

var _ Provider = (*OIDCProvider)(nil)

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *OIDCProvider) Redeem(ctx context.Context, redirectURL, code string) (s *sessions.SessionState, err error) {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return
	}

	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
		RedirectURL: redirectURL,
	}
	token, err := c.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %v", err)
	}

	// in the initial exchange the id token is mandatory
	idToken, err := p.findVerifiedIDToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("could not verify id_token: %v", err)
	} else if idToken == nil {
		return nil, fmt.Errorf("token response did not contain an id_token")
	}

	s, err = p.createSessionState(ctx, token, idToken)
	if err != nil {
		return nil, fmt.Errorf("unable to update session: %v", err)
	}

	return
}

// RefreshSessionIfNeeded checks if the session has expired and uses the
// RefreshToken to fetch a new Access Token (and optional ID token) if required
func (p *OIDCProvider) RefreshSessionIfNeeded(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if s == nil || (s.ExpiresOn != nil && s.ExpiresOn.After(time.Now())) || s.RefreshToken == "" {
		return false, nil
	}

	err := p.redeemRefreshToken(ctx, s)
	if err != nil {
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	fmt.Printf("refreshed access token %s (expired on %s)\n", s, s.ExpiresOn)
	return true, nil
}

func (p *OIDCProvider) redeemRefreshToken(ctx context.Context, s *sessions.SessionState) (err error) {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return
	}

	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
	}
	t := &oauth2.Token{
		RefreshToken: s.RefreshToken,
		Expiry:       time.Now().Add(-time.Hour),
	}
	token, err := c.TokenSource(ctx, t).Token()
	if err != nil {
		return fmt.Errorf("failed to get token: %v", err)
	}

	// in the token refresh response the id_token is optional
	idToken, err := p.findVerifiedIDToken(ctx, token)
	if err != nil {
		return fmt.Errorf("unable to extract id_token from response: %v", err)
	}

	newSession, err := p.createSessionState(ctx, token, idToken)
	if err != nil {
		return fmt.Errorf("unable create new session state from response: %v", err)
	}

	// It's possible that if the refresh token isn't in the token response the session will not contain an id token
	// if it doesn't it's probably better to retain the old one
	if newSession.IDToken != "" {
		s.IDToken = newSession.IDToken
		s.Email = newSession.Email
		s.User = newSession.User
		s.PreferredUsername = newSession.PreferredUsername
	}

	s.AccessToken = newSession.AccessToken
	s.RefreshToken = newSession.RefreshToken
	s.CreatedAt = newSession.CreatedAt
	s.ExpiresOn = newSession.ExpiresOn

	return
}

func (p *OIDCProvider) findVerifiedIDToken(ctx context.Context, token *oauth2.Token) (*oidc.IDToken, error) {

	getIDToken := func() (string, bool) {
		rawIDToken, _ := token.Extra("id_token").(string)
		return rawIDToken, len(strings.TrimSpace(rawIDToken)) > 0
	}

	if rawIDToken, present := getIDToken(); present {
		verifiedIDToken, err := p.Verifier.Verify(ctx, rawIDToken)
		return verifiedIDToken, err
	}
	return nil, nil
}

func (p *OIDCProvider) createSessionState(ctx context.Context, token *oauth2.Token, idToken *oidc.IDToken) (*sessions.SessionState, error) {

	var newSession *sessions.SessionState

	if idToken == nil {
		newSession = &sessions.SessionState{}
	} else {
		var err error
		newSession, err = p.createSessionStateInternal(ctx, token.Extra("id_token").(string), idToken, token)
		if err != nil {
			return nil, err
		}
	}

	created := time.Now()
	newSession.AccessToken = token.AccessToken
	newSession.RefreshToken = token.RefreshToken
	newSession.CreatedAt = &created
	newSession.ExpiresOn = &token.Expiry
	return newSession, nil
}

func (p *OIDCProvider) CreateSessionStateFromBearerToken(ctx context.Context, rawIDToken string, idToken *oidc.IDToken) (*sessions.SessionState, error) {
	newSession, err := p.createSessionStateInternal(ctx, rawIDToken, idToken, nil)
	if err != nil {
		return nil, err
	}

	newSession.AccessToken = rawIDToken
	newSession.IDToken = rawIDToken
	newSession.RefreshToken = ""
	newSession.ExpiresOn = &idToken.Expiry

	return newSession, nil
}

func (p *OIDCProvider) createSessionStateInternal(ctx context.Context, rawIDToken string, idToken *oidc.IDToken, token *oauth2.Token) (*sessions.SessionState, error) {

	newSession := &sessions.SessionState{}

	if idToken == nil {
		return newSession, nil
	}
	accessToken := ""
	if token != nil {
		accessToken = token.AccessToken
	}

	claims, err := p.findClaimsFromIDToken(ctx, idToken, accessToken, p.ProfileURL.String())
	if err != nil {
		return nil, fmt.Errorf("couldn't extract claims from id_token (%v)", err)
	}

	newSession.IDToken = rawIDToken

	newSession.Email = claims.UserID // TODO Rename SessionState.Email to .UserID in the near future

	newSession.User = claims.Subject
	newSession.PreferredUsername = claims.PreferredUsername

	verifyEmail := (p.UserIDClaim == emailClaim) && !p.AllowUnverifiedEmail
	if verifyEmail && claims.Verified != nil && !*claims.Verified {
		return nil, fmt.Errorf("email in id_token (%s) isn't verified", claims.UserID)
	}

	return newSession, nil
}

// ValidateSessionState checks that the session's IDToken is still valid
func (p *OIDCProvider) ValidateSessionState(ctx context.Context, s *sessions.SessionState) bool {
	_, err := p.Verifier.Verify(ctx, s.IDToken)
	return err == nil
}

func getOIDCHeader(accessToken string) http.Header {
	header := make(http.Header)
	header.Set("Accept", "application/json")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	return header
}

func (p *OIDCProvider) findClaimsFromIDToken(ctx context.Context, idToken *oidc.IDToken, accessToken string, profileURL string) (*OIDCClaims, error) {

	claims := &OIDCClaims{}
	// Extract default claims.
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse default id_token claims: %v", err)
	}
	// Extract custom claims.
	if err := idToken.Claims(&claims.rawClaims); err != nil {
		return nil, fmt.Errorf("failed to parse all id_token claims: %v", err)
	}

	userID := claims.rawClaims[p.UserIDClaim]
	if userID != nil {
		claims.UserID = fmt.Sprint(userID)
	}

	// userID claim was not present or was empty in the ID Token
	if claims.UserID == "" {
		if profileURL == "" {
			return nil, fmt.Errorf("id_token did not contain user ID claim (%q)", p.UserIDClaim)
		}

		// If the userinfo endpoint profileURL is defined, then there is a chance the userinfo
		// contents at the profileURL contains the email.
		// Make a query to the userinfo endpoint, and attempt to locate the email from there.
		respJSON, err := requests.New(profileURL).
			WithContext(ctx).
			WithHeaders(getOIDCHeader(accessToken)).
			Do().
			UnmarshalJSON()
		if err != nil {
			return nil, err
		}

		userID, err := respJSON.Get(p.UserIDClaim).String()
		if err != nil {
			return nil, fmt.Errorf("neither id_token nor userinfo endpoint contained user ID claim (%q)", p.UserIDClaim)
		}

		claims.UserID = userID
	}

	return claims, nil
}

type OIDCClaims struct {
	rawClaims         map[string]interface{}
	UserID            string
	Subject           string `json:"sub"`
	Verified          *bool  `json:"email_verified"`
	PreferredUsername string `json:"preferred_username"`
}
