package providers

import (
	"context"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

// Provider represents an upstream identity provider implementation
type Provider interface {
	Data() *ProviderData
	// Deprecated: Migrate to EnrichSession
	GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error)
	Redeem(ctx context.Context, redirectURI, code string) (*sessions.SessionState, error)
	EnrichSession(ctx context.Context, s *sessions.SessionState) error
	Authorize(ctx context.Context, s *sessions.SessionState) (bool, error)
	ValidateSession(ctx context.Context, s *sessions.SessionState) bool
	GetLoginURL(redirectURI, finalRedirect string) string
	RefreshSessionIfNeeded(ctx context.Context, s *sessions.SessionState) (bool, error)
	CreateSessionFromToken(ctx context.Context, token string) (*sessions.SessionState, error)
}

// New provides a new Provider based on the configured provider string
func New(provider string, p *ProviderData) Provider {
	switch provider {
	case "linkedin":
		return NewLinkedInProvider(p)
	case "facebook":
		return NewFacebookProvider(p)
	case "github":
		return NewGitHubProvider(p)
	case "keycloak":
		return NewKeycloakProvider(p)
	case "azure":
		return NewAzureProvider(p)
	case "gitlab":
		return NewGitLabProvider(p)
	case "oidc":
		return NewOIDCProvider(p)
	case "login.gov":
		return NewLoginGovProvider(p)
	case "bitbucket":
		return NewBitbucketProvider(p)
	case "nextcloud":
		return NewNextcloudProvider(p)
	case "digitalocean":
		return NewDigitalOceanProvider(p)
	case "google":
		return NewGoogleProvider(p)
	default:
		return nil
	}
}
