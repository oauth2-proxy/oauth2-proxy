package providers

import (
	"context"
	"fmt"
	"net/url"

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
func NewKeycloakProvider(p *ProviderData) *KeycloakProvider {
	p.setProviderDefaults(providerDefaults{
		name:        keycloakProviderName,
		loginURL:    keycloakDefaultLoginURL,
		redeemURL:   keycloakDefaultRedeemURL,
		profileURL:  nil,
		validateURL: keycloakDefaultValidateURL,
		scope:       keycloakDefaultScope,
	})
	return &KeycloakProvider{ProviderData: p}
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
		SetHeader("Authorization", "Bearer "+s.AccessToken).
		Do().
		UnmarshalJSON()
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

	fullName, err := json.Get("name").String()
	if err != nil {
		return fmt.Errorf("unable to extract name from userinfo endpoint: %v", err)
	}
	s.User = fullName

	username, err := json.Get("preferred_username").String()
	if err != nil {
		return fmt.Errorf("unable to extract preferred_username from userinfo endpoint: %v", err)
	}
	s.PreferredUsername = username

	return nil
}
