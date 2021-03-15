package providers

import (
	"context"
	"fmt"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
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

// AddAllowedRoles sets Keycloak roles that are authorized.
// Assumes `SetAllowedGroups` is already called on groups and appends to that
// with `role:` prefixed roles.
func (p *KeycloakOIDCProvider) AddAllowedRoles(roles []string) {
	for _, role := range roles {
		p.AllowedGroups[formatRole(role)] = struct{}{}
	}
}

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
// "resource_access": {
//   "clientA": {
//     "roles": [
//       "roleA"
//     ]
//   },
//   "clientB": {
//     "roles": [
//       "roleA",
//       "roleB",
//       "roleC"
//     ]
//   }
// }
func getClientRoles(claims *accessClaims) []string {
	var clientRoles []string
	for clientName, access := range claims.ResourceAccess {
		accessMap, ok := access.(map[string]interface{})
		if !ok {
			logger.Errorf("Unable to parse client roles from claims for client: %v", clientName)
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
