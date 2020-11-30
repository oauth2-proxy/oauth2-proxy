package providers

import (
	"context"
	"fmt"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
	"golang.org/x/oauth2"
)

// GitLabProvider represents a GitLab based Identity Provider
type GitLabProvider struct {
	*ProviderData

	Groups               []string
	Verifier             *oidc.IDTokenVerifier
	AllowUnverifiedEmail bool
}

var _ Provider = (*GitLabProvider)(nil)

const (
	gitlabProviderName = "GitLab"
	gitlabDefaultScope = "openid email"
)

// NewGitLabProvider initiates a new GitLabProvider
func NewGitLabProvider(p *ProviderData) *GitLabProvider {
	p.ProviderName = gitlabProviderName

	if p.Scope == "" {
		p.Scope = gitlabDefaultScope
	}

	return &GitLabProvider{ProviderData: p}
}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *GitLabProvider) Redeem(ctx context.Context, redirectURL, code string) (s *sessions.SessionState, err error) {
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
	s, err = p.createSessionState(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("unable to update session: %v", err)
	}
	return
}

// RefreshSessionIfNeeded checks if the session has expired and uses the
// RefreshToken to fetch a new ID token if required
func (p *GitLabProvider) RefreshSessionIfNeeded(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if s == nil || (s.ExpiresOn != nil && s.ExpiresOn.After(time.Now())) || s.RefreshToken == "" {
		return false, nil
	}

	origExpiration := s.ExpiresOn

	err := p.redeemRefreshToken(ctx, s)
	if err != nil {
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	fmt.Printf("refreshed id token %s (expired on %s)\n", s, origExpiration)
	return true, nil
}

func (p *GitLabProvider) redeemRefreshToken(ctx context.Context, s *sessions.SessionState) (err error) {
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
	newSession, err := p.createSessionState(ctx, token)
	if err != nil {
		return fmt.Errorf("unable to update session: %v", err)
	}
	s.AccessToken = newSession.AccessToken
	s.IDToken = newSession.IDToken
	s.RefreshToken = newSession.RefreshToken
	s.CreatedAt = newSession.CreatedAt
	s.ExpiresOn = newSession.ExpiresOn
	s.Email = newSession.Email
	return
}

type gitlabUserInfo struct {
	Username      string   `json:"nickname"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Groups        []string `json:"groups"`
}

func (p *GitLabProvider) getUserInfo(ctx context.Context, s *sessions.SessionState) (*gitlabUserInfo, error) {
	// Retrieve user info JSON
	// https://docs.gitlab.com/ee/integration/openid_connect_provider.html#shared-information

	// Build user info url from login url of GitLab instance
	userInfoURL := *p.LoginURL
	userInfoURL.Path = "/oauth/userinfo"

	var userInfo gitlabUserInfo
	err := requests.New(userInfoURL.String()).
		WithContext(ctx).
		SetHeader("Authorization", "Bearer "+s.AccessToken).
		Do().
		UnmarshalInto(&userInfo)
	if err != nil {
		return nil, fmt.Errorf("error getting user info: %v", err)
	}

	return &userInfo, nil
}

func (p *GitLabProvider) verifyGroupMembership(userInfo *gitlabUserInfo) error {
	if len(p.Groups) == 0 {
		return nil
	}

	// Collect user group memberships
	membershipSet := make(map[string]bool)
	for _, group := range userInfo.Groups {
		membershipSet[group] = true
	}

	// Find a valid group that they are a member of
	for _, validGroup := range p.Groups {
		if _, ok := membershipSet[validGroup]; ok {
			return nil
		}
	}

	return fmt.Errorf("user is not a member of '%s'", p.Groups)
}

func (p *GitLabProvider) createSessionState(ctx context.Context, token *oauth2.Token) (*sessions.SessionState, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("token response did not contain an id_token")
	}

	// Parse and verify ID Token payload.
	idToken, err := p.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("could not verify id_token: %v", err)
	}

	created := time.Now()
	return &sessions.SessionState{
		AccessToken:  token.AccessToken,
		IDToken:      rawIDToken,
		RefreshToken: token.RefreshToken,
		CreatedAt:    &created,
		ExpiresOn:    &idToken.Expiry,
	}, nil
}

// ValidateSession checks that the session's IDToken is still valid
func (p *GitLabProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	_, err := p.Verifier.Verify(ctx, s.IDToken)
	return err == nil
}

// GetEmailAddress returns the Account email address
func (p *GitLabProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	// Retrieve user info
	userInfo, err := p.getUserInfo(ctx, s)
	if err != nil {
		return fmt.Errorf("failed to retrieve user info: %v", err)
	}

	// Check if email is verified
	if !p.AllowUnverifiedEmail && !userInfo.EmailVerified {
		return fmt.Errorf("user email is not verified")
	}

	// Check group membership
	// TODO (@NickMeves) - Refactor to Authorize
	err = p.verifyGroupMembership(userInfo)
	if err != nil {
		return fmt.Errorf("group membership check failed: %v", err)
	}

	s.User = userInfo.Username
	s.Email = userInfo.Email

	return nil
}
