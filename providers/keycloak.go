package providers

import (
	"context"
	"fmt"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

type KeycloakProvider struct {
	*ProviderData
}

var _ Provider = (*KeycloakProvider)(nil)

const (
	keycloakProviderName = "Keycloak"
	keycloakDefaultScope = "api"
)

var (
	// Default Login URL for Keycloak.
	// Pre-parsed URL of https://keycloak.org/oauth/authorize.
	keycloakDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "keycloak.org",
		Path:   "/oauth/authorize",
	}

	// Default Redeem URL for Keycloak.
	// Pre-parsed URL of ttps://keycloak.org/oauth/token.
	keycloakDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "keycloak.org",
		Path:   "/oauth/token",
	}

	// Default Validation URL for Keycloak.
	// Pre-parsed URL of https://keycloak.org/api/v3/user.
	keycloakDefaultValidateURL = &url.URL{
		Scheme: "https",
		Host:   "keycloak.org",
		Path:   "/api/v3/user",
	}
)

// NewKeycloakProvider creates a KeyCloakProvider using the passed ProviderData
func NewKeycloakProvider(p *ProviderData, opts options.KeycloakOptions) *KeycloakProvider {
	p.setProviderDefaults(providerDefaults{
		name:        keycloakProviderName,
		loginURL:    keycloakDefaultLoginURL,
		redeemURL:   keycloakDefaultRedeemURL,
		profileURL:  nil,
		validateURL: keycloakDefaultValidateURL,
		scope:       keycloakDefaultScope,
	})

	provider := &KeycloakProvider{ProviderData: p}
	provider.setAllowedGroups(opts.Groups)
	return provider
}

// EnrichSession uses the Keycloak userinfo endpoint to populate the session's
// email and groups.
func (p *KeycloakProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	// Fallback to ValidateURL if ProfileURL not set for legacy compatibility
	profileURL := p.ValidateURL.String()
	if p.ProfileURL.String() != "" {
		profileURL = p.ProfileURL.String()
	}

	json, err := requests.New(profileURL).
		WithContext(ctx).
		WithClient(p.Client).
		SetHeader("Authorization", tokenTypeBearer+" "+s.AccessToken).
		Do().
		UnmarshalSimpleJSON()
	if err != nil {
		logger.Errorf("failed making request %v", err)
		return err
	}

	groups, err := json.Get("groups").StringArray()
	if err == nil {
		for _, group := range groups {
			if group != "" {
				s.Groups = append(s.Groups, group)
			}
		}
	}

	email, err := json.Get("email").String()
	if err != nil {
		return fmt.Errorf("unable to extract email from userinfo endpoint: %v", err)
	}
	s.Email = email

	preferredUsername, err := json.Get("preferred_username").String()
	if err == nil {
		s.PreferredUsername = preferredUsername
	}

	user, err := json.Get("user").String()
	if err == nil {
		s.User = user
	}

	if s.User == "" && s.PreferredUsername != "" {
		s.User = s.PreferredUsername
	}

	return nil
}

// ValidateSession validates the AccessToken
func (p *KeycloakProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
}
