package providers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/requests"
)

// OIDCProvider represents an OIDC based Identity Provider
type OIDCProvider struct {
	*ProviderData

	Verifier             *oidc.IDTokenVerifier
	AllowUnverifiedEmail bool
	UserIDClaims         []string
}

// NewOIDCProvider initiates a new OIDCProvider
func NewOIDCProvider(p *ProviderData) *OIDCProvider {
	p.ProviderName = "OpenID Connect"
	return &OIDCProvider{ProviderData: p}
}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *OIDCProvider) Redeem(redirectURL, code string) (s *sessions.SessionState, err error) {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return
	}

	ctx := context.Background()
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

	s, err = p.createSessionState(token, idToken)
	if err != nil {
		return nil, fmt.Errorf("unable to update session: %v", err)
	}

	return
}

// RefreshSessionIfNeeded checks if the session has expired and uses the
// RefreshToken to fetch a new Access Token (and optional ID token) if required
func (p *OIDCProvider) RefreshSessionIfNeeded(s *sessions.SessionState) (bool, error) {
	if s == nil || s.ExpiresOn.After(time.Now()) || s.RefreshToken == "" {
		return false, nil
	}

	err := p.redeemRefreshToken(s)
	if err != nil {
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	fmt.Printf("refreshed access token %s (expired on %s)\n", s, s.ExpiresOn)
	return true, nil
}

func (p *OIDCProvider) redeemRefreshToken(s *sessions.SessionState) (err error) {
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
	ctx := context.Background()
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

	newSession, err := p.createSessionState(token, idToken)
	if err != nil {
		return fmt.Errorf("unable create new session state from response: %v", err)
	}

	// It's possible that if the refresh token isn't in the token response the session will not contain an id token
	// if it doesn't it's probably better to retain the old one
	if newSession.IDToken != "" {
		s.IDToken = newSession.IDToken
		s.UserID = newSession.UserID
		s.UserIDType = newSession.UserIDType
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

func (p *OIDCProvider) createSessionState(token *oauth2.Token, idToken *oidc.IDToken) (*sessions.SessionState, error) {

	newSession := &sessions.SessionState{}

	if idToken != nil {
		fmt.Println("UserIDClaims=", p.UserIDClaims) // FIXME rm
		claims, err := findClaimsFromIDToken(idToken, token.AccessToken, p.ProfileURL.String(), p.UserIDClaims)
		if err != nil {
			return nil, fmt.Errorf("couldn't extract claims from id_token (%e)", err)
		}

		if claims != nil {

			if !p.AllowUnverifiedEmail && claims.Verified != nil && !*claims.Verified {
				return nil, fmt.Errorf("email in id_token (%s) isn't verified", claims.Email)
			}

			newSession.IDToken = token.Extra("id_token").(string)

			newSession.UserID = claims.UserID
			newSession.UserIDType = claims.UserIDType

			newSession.User = claims.Subject
			newSession.PreferredUsername = claims.PreferredUsername
		}
	}

	newSession.AccessToken = token.AccessToken
	newSession.RefreshToken = token.RefreshToken
	newSession.CreatedAt = time.Now()
	newSession.ExpiresOn = token.Expiry
	return newSession, nil
}

// ValidateSessionState checks that the session's IDToken is still valid
func (p *OIDCProvider) ValidateSessionState(s *sessions.SessionState) bool {
	ctx := context.Background()
	_, err := p.Verifier.Verify(ctx, s.IDToken)
	if err != nil {
		return false
	}

	return true
}

func getOIDCHeader(accessToken string) http.Header {
	header := make(http.Header)
	header.Set("Accept", "application/json")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	return header
}

func findClaimsFromIDToken(idToken *oidc.IDToken, accessToken string, profileURL string, userIDClaims []string) (*OIDCClaims, error) {

	// Extract custom claims.
	claims := &OIDCClaims{}
	if err := idToken.Claims(claims); err != nil {
		return nil, fmt.Errorf("failed to parse id_token claims: %v", err)
	}

	for _, userIDClaim := range userIDClaims {
		if claims.UserID != "" {
			break
		} else if userIDClaim == "email" {
			if claims.Email == "" {
				claims.Email, _ = tryFetchEmail(claims.Email, accessToken, profileURL)
			}
			claims.UserID = claims.Email
			claims.UserIDType = userIDClaim
		} else if userIDClaim == "phone_number" {
			claims.UserID = claims.PhoneNumber
			claims.UserIDType = userIDClaim
		} else {
			return nil, fmt.Errorf("asked for the unsupported used-id-claim '%s'; supported: email, phone_number",
				userIDClaim)
		}
	}

	if claims.UserID == "" {
		return nil, fmt.Errorf("id_token contained none of the user id claims %v", userIDClaims)
	}

	fmt.Println("DBG>>> ODIC: UserID=", claims.UserID) // FIXME rm

	return claims, nil
}

func tryFetchEmail(emailClaim string, accessToken string, profileURL string) (string, error) {
	if emailClaim != "" {
		return emailClaim, nil
	}

	if profileURL == "" {
		return "", fmt.Errorf("id_token did not contain an email and no profile-url for trying to fetch it specified")
	}

	// If the userinfo endpoint profileURL is defined, then there is a chance the userinfo
	// contents at the profileURL contains the email.
	// Make a query to the userinfo endpoint, and attempt to locate the email from there.

	req, err := http.NewRequest("GET", profileURL, nil)
	if err != nil {
		return "", err
	}
	req.Header = getOIDCHeader(accessToken)

	respJSON, err := requests.Request(req)
	if err != nil {
		return "", err
	}

	email, err := respJSON.Get("email").String()
	if err != nil {
		return "", fmt.Errorf("neither id_token nor userinfo endpoint contained an email")
	}

	return email, nil
}

type OIDCClaims struct {
	UserID              string `json:"-"` // Derived from other fields
	UserIDType          string `json:"-"` // Derived from other fields
	Subject             string `json:"sub"`
	Email               string `json:"email"`
	PhoneNumber         string `json:"phone_number"`
	PhoneNumberVerified *bool  `json:"phone_number_verified"`
	Verified            *bool  `json:"email_verified"`
	PreferredUsername   string `json:"preferred_username"`
}
