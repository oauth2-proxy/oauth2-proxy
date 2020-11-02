package providers

import (
	"context"

	"github.com/coreos/go-oidc"
	mw "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

// Provider represents an upstream identity provider implementation
type Provider interface {
	Data() *ProviderData
	// DEPRECATED: Migrate to EnrichSessionState
	GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error)
	Redeem(ctx context.Context, ps mw.ProxyState, redirectURI, code string) (*sessions.SessionState, error)
	ValidateGroup(string) bool
	EnrichSessionState(ctx context.Context, ps mw.ProxyState, s *sessions.SessionState) error
	ValidateSessionState(ctx context.Context, ps mw.ProxyState, s *sessions.SessionState) bool
	GetLoginURL(redirectURI, finalRedirect string) string
	RefreshSessionIfNeeded(ctx context.Context, ps mw.ProxyState, s *sessions.SessionState) (bool, error)
	CreateSessionStateFromBearerToken(ctx context.Context, ps mw.ProxyState, rawIDToken string, idToken *oidc.IDToken) (*sessions.SessionState, error)
}

// New provides a new Provider based on the configured provider string
func New(provider string, p *ProviderData) Provider {
	logger.Printf("setting provider to '%s'", provider)
	switch provider {
	case "google":
		return NewGoogleProvider(p)
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
		logger.Errorf("unknown provider '%s', defaulting to 'google'", provider)
		return NewGoogleProvider(p)
	}
}
