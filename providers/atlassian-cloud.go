package providers

import (
	"context"
	"errors"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// AtlassianProvider represents an Atlassian based Identity Provider
type AtlassianProvider struct {
	*ProviderData
}

var _ Provider = (*AtlassianProvider)(nil)

const (
	atlassianProviderName = "Atlassian"
	atlassianDefaultScope = "read:me"
	atlassianPrompt       = "consent"
	atlassianAudience     = "api.atlassian.com"
)

var (
	// Default Login URL for Atlassian.
	// Pre-parsed URL of https://atlassian.org/site/oauth2/authorize.
	atlassianDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "auth.atlassian.com",
		Path:   "/authorize",
	}

	// Default Redeem URL for Atlassian.
	// Pre-parsed URL of https://atlassian.org/site/oauth2/access_token.
	atlassianDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "auth.atlassian.com",
		Path:   "/oauth/token",
	}

	// Default Validation URL for Atlassian.
	// This simply returns the email of the authenticated user.
	// Atlassian does not have a Profile URL to use.
	// Pre-parsed URL of https://api.atlassian.org/2.0/user/emails.
	atlassianDefaultValidateURL = &url.URL{
		Scheme: "https",
		Host:   "api.atlassian.com",
		Path:   "/me",
	}
)

// NewAtlassianProvider initiates a new AtlassianProvider
func NewAtlassianProvider(p *ProviderData) *AtlassianProvider {
	p.setProviderDefaults(providerDefaults{
		name:        atlassianProviderName,
		loginURL:    atlassianDefaultLoginURL,
		redeemURL:   atlassianDefaultRedeemURL,
		profileURL:  nil,
		validateURL: atlassianDefaultValidateURL,
		scope:       atlassianDefaultScope,
	})
	p.Prompt = atlassianPrompt
	return &AtlassianProvider{ProviderData: p}
}
func (p *AtlassianProvider) GetLoginURL(redirectURI, state, _ string) string {
	extraParams := url.Values{}
	extraParams.Add("audience", atlassianAudience)
	loginURL := makeLoginURL(p.ProviderData, redirectURI, state, extraParams)
	return loginURL.String()
}
func (p *AtlassianProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
}
func (p *AtlassianProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	type meEmail struct {
		Email string `json:"email"`
	}
	var email meEmail
	err := requests.New(atlassianDefaultValidateURL.String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(s.AccessToken)).
		Do().
		UnmarshalInto(&email)

	if err != nil {
		return "", err
	}
	if email.Email == "" {
		return "", errors.New("no email in respose")
	}
	return email.Email, nil
}
