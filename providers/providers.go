package providers

import (
	"context"

	"github.com/coreos/go-oidc"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
)

// Provider represents an upstream identity provider implementation
type Provider interface {
	Data() *ProviderData
	GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error)
	GetUserName(ctx context.Context, s *sessions.SessionState) (string, error)
	GetPreferredUsername(ctx context.Context, s *sessions.SessionState) (string, error)
	Redeem(ctx context.Context, redirectURI, code string) (*sessions.SessionState, error)
	ValidateGroup(string) bool
	ValidateSessionState(ctx context.Context, s *sessions.SessionState) bool
	GetLoginURL(redirectURI, finalRedirect string) string
	RefreshSessionIfNeeded(ctx context.Context, s *sessions.SessionState) (bool, error)
	CreateSessionStateFromBearerToken(ctx context.Context, rawIDToken string, idToken *oidc.IDToken) (*sessions.SessionState, error)
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
	default:
		return NewGoogleProvider(p)
	}
}
