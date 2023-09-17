package providers

import (
	"context"
	"fmt"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

const keycloakOIDCProviderName = "Keycloak OIDC"

// KeycloakOIDCProvider creates a Keycloak provider based on OIDCProvider
type KeycloakOIDCProvider struct {
	*OIDCProvider
}

// NewKeycloakOIDCProvider makes a KeycloakOIDCProvider using the ProviderData
func NewKeycloakOIDCProvider(p *ProviderData, opts options.KeycloakOptions) *KeycloakOIDCProvider {
	p.setProviderDefaults(providerDefaults{
		name: keycloakOIDCProviderName,
	})

	provider := &KeycloakOIDCProvider{
		OIDCProvider: NewOIDCProvider(p, options.OIDCOptions{InsecureSkipNonce: false}),
	}

	provider.addAllowedRoles(opts.Roles)
	return provider
}

var _ Provider = (*KeycloakOIDCProvider)(nil)

// addAllowedRoles sets Keycloak roles that are authorized.
// Assumes `SetAllowedGroups` is already called on groups and appends to that
// with `role:` prefixed roles.
func (p *KeycloakOIDCProvider) addAllowedRoles(roles []string) {
	if p.AllowedGroups == nil {
		p.AllowedGroups = make(map[string]struct{})
	}
	for _, role := range roles {
		p.AllowedGroups[formatRole(role)] = struct{}{}
	}
}

// CreateSessionFromToken converts Bearer IDTokens into sessions
func (p *KeycloakOIDCProvider) CreateSessionFromToken(ctx context.Context, token string) (*sessions.SessionState, error) {
	ss, err := p.OIDCProvider.CreateSessionFromToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("could not create session from token: %v", err)
	}

	// Extract custom keycloak roles and enrich session
	if err := p.extractRoles(ctx, ss); err != nil {
		return nil, err
	}

	return ss, nil
}

// EnrichSession is called after Redeem to allow providers to enrich session fields
// such as User, Email, Groups with provider specific API calls.
func (p *KeycloakOIDCProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	err := p.OIDCProvider.EnrichSession(ctx, s)
	if err != nil {
		return fmt.Errorf("could not enrich oidc session: %v", err)
	}
	return p.extractRoles(ctx, s)
}

// RefreshSession adds role extraction logic to the refresh flow
func (p *KeycloakOIDCProvider) RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error) {
	refreshed, err := p.OIDCProvider.RefreshSession(ctx, s)

	// Refresh could have failed or there was not session to refresh (with no error raised)
	if err != nil || !refreshed {
		return refreshed, err
	}

	return true, p.extractRoles(ctx, s)
}

func (p *KeycloakOIDCProvider) extractRoles(ctx context.Context, s *sessions.SessionState) error {
	claims, err := p.getAccessClaims(ctx, s)
	if err != nil {
		return err
	}

	var roles []string
	roles = append(roles, claims.RealmAccess.Roles...)
	roles = append(roles, getClientRoles(claims)...)

	// Add to groups list with `role:` prefix to distinguish from groups
	for _, role := range roles {
		s.Groups = append(s.Groups, formatRole(role))
	}
	return nil
}

type realmAccess struct {
	Roles []string `json:"roles"`
}

type accessClaims struct {
	RealmAccess    realmAccess            `json:"realm_access"`
	ResourceAccess map[string]interface{} `json:"resource_access"`
}

func (p *KeycloakOIDCProvider) getAccessClaims(ctx context.Context, s *sessions.SessionState) (*accessClaims, error) {
	// HACK: This isn't an ID Token, but has similar structure & signing
	token, err := p.Verifier.Verify(ctx, s.AccessToken)
	if err != nil {
		return nil, err
	}

	var claims *accessClaims
	if err = token.Claims(&claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// getClientRoles extracts client roles from the `resource_access` claim with
// the format `client:role`.
//
// ResourceAccess format:
//
//	"resource_access": {
//	  "clientA": {
//	    "roles": [
//	      "roleA"
//	    ]
//	  },
//	  "clientB": {
//	    "roles": [
//	      "roleA",
//	      "roleB",
//	      "roleC"
//	    ]
//	  }
//	}
func getClientRoles(claims *accessClaims) []string {
	var clientRoles []string
	for clientName, access := range claims.ResourceAccess {
		accessMap, ok := access.(map[string]interface{})
		if !ok {
			continue
		}

		var roles interface{}
		if roles, ok = accessMap["roles"]; !ok {
			continue
		}
		for _, role := range roles.([]interface{}) {
			clientRoles = append(clientRoles, fmt.Sprintf("%s:%s", clientName, role))
		}
	}
	return clientRoles
}

func formatRole(role string) string {
	return fmt.Sprintf("role:%s", role)
}
