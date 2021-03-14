package providers

import (
	"context"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

const keycloakOIDCProviderName = "Keycloak OIDC"

// KeycloakOIDCProvider creates a Keycloak provider based on OIDCProvider
type KeycloakOIDCProvider struct {
	*OIDCProvider
}

// NewKeycloakOIDCProvider makes a KeycloakOIDCProvider using the ProviderData
func NewKeycloakOIDCProvider(p *ProviderData) *KeycloakOIDCProvider {
	p.ProviderName = keycloakOIDCProviderName
	return &KeycloakOIDCProvider{
		OIDCProvider: &OIDCProvider{
			ProviderData: p,
		},
	}
}

var _ Provider = (*KeycloakOIDCProvider)(nil)

// EnrichSession is called after Redeem to allow providers to enrich session fields
// such as User, Email, Groups with provider specific API calls.
func (p *KeycloakOIDCProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	err := p.OIDCProvider.EnrichSession(ctx, s)
	if err != nil {
		return err
	}
	return p.extractRoles(ctx, s)
}

func (p *KeycloakOIDCProvider) extractRoles(ctx context.Context, s *sessions.SessionState) error {
	// TODO: Implement me with Access Token Role claim extraction logic
	return ErrNotImplemented
}
