package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"golang.org/x/oauth2"
)

// GitLabProvider represents a GitLab based Identity Provider
type GitLabProvider struct {
	*ProviderData

	Group        string
	EmailDomains []string

	Verifier             *oidc.IDTokenVerifier
	AllowUnverifiedEmail bool
}

// NewGitLabProvider initiates a new GitLabProvider
func NewGitLabProvider(p *ProviderData) *GitLabProvider {
	p.ProviderName = "GitLab"

	if p.Scope == "" {
		p.Scope = "openid email"
	}

	return &GitLabProvider{ProviderData: p}
}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *GitLabProvider) Redeem(redirectURL, code string) (s *sessions.SessionState, err error) {
	ctx := context.Background()
	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
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
func (p *GitLabProvider) RefreshSessionIfNeeded(s *sessions.SessionState) (bool, error) {
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

func (p *GitLabProvider) redeemRefreshToken(s *sessions.SessionState) (err error) {
	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
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

func (p *GitLabProvider) getUserInfo(s *sessions.SessionState) (*gitlabUserInfo, error) {
	// Retrieve user info JSON
	// https://docs.gitlab.com/ee/integration/openid_connect_provider.html#shared-information

	// Build user info url from login url of GitLab instance
	userInfoURL := *p.LoginURL
	userInfoURL.Path = "/oauth/userinfo"

	req, err := http.NewRequest("GET", userInfoURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user info request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.AccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform user info request: %v", err)
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to read user info response: %v", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("got %d during user info request: %s", resp.StatusCode, body)
	}

	var userInfo gitlabUserInfo
	err = json.Unmarshal(body, &userInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user info: %v", err)
	}

	return &userInfo, nil
}

func (p *GitLabProvider) verifyGroupMembership(userInfo *gitlabUserInfo) error {
	if p.Group == "" {
		return nil
	}

	// Collect user group memberships
	membershipSet := make(map[string]bool)
	for _, group := range userInfo.Groups {
		membershipSet[group] = true
	}

	// Find a valid group that they are a member of
	validGroups := strings.Split(p.Group, " ")
	for _, validGroup := range validGroups {
		if _, ok := membershipSet[validGroup]; ok {
			return nil
		}
	}

	return fmt.Errorf("user is not a member of '%s'", p.Group)
}

func (p *GitLabProvider) verifyEmailDomain(userInfo *gitlabUserInfo) error {
	if len(p.EmailDomains) == 0 || p.EmailDomains[0] == "*" {
		return nil
	}

	for _, domain := range p.EmailDomains {
		if strings.HasSuffix(userInfo.Email, domain) {
			return nil
		}
	}

	return fmt.Errorf("user email is not one of the valid domains '%v'", p.EmailDomains)
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

	return &sessions.SessionState{
		AccessToken:  token.AccessToken,
		IDToken:      rawIDToken,
		RefreshToken: token.RefreshToken,
		CreatedAt:    time.Now(),
		ExpiresOn:    idToken.Expiry,
	}, nil
}

// ValidateSessionState checks that the session's IDToken is still valid
func (p *GitLabProvider) ValidateSessionState(s *sessions.SessionState) bool {
	ctx := context.Background()
	_, err := p.Verifier.Verify(ctx, s.IDToken)
	if err != nil {
		return false
	}

	return true
}

// GetEmailAddress returns the Account email address
func (p *GitLabProvider) GetEmailAddress(s *sessions.SessionState) (string, error) {
	// Retrieve user info
	userInfo, err := p.getUserInfo(s)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve user info: %v", err)
	}

	// Check if email is verified
	if !p.AllowUnverifiedEmail && !userInfo.EmailVerified {
		return "", fmt.Errorf("user email is not verified")
	}

	// Check if email has valid domain
	err = p.verifyEmailDomain(userInfo)
	if err != nil {
		return "", fmt.Errorf("email domain check failed: %v", err)
	}

	// Check group membership
	err = p.verifyGroupMembership(userInfo)
	if err != nil {
		return "", fmt.Errorf("group membership check failed: %v", err)
	}

	return userInfo.Email, nil
}

// GetUserName returns the Account user name
func (p *GitLabProvider) GetUserName(s *sessions.SessionState) (string, error) {
	userInfo, err := p.getUserInfo(s)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve user info: %v", err)
	}

	return userInfo.Username, nil
}
