package providers

import (
	"context"
	"errors"
	"net/url"

	"github.com/bitly/go-simplejson"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/requests"
)

type KeycloakProvider struct {
	*ProviderData
	Group       string
	UserIDClaim string
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

func (p *KeycloakProvider) SetGroup(group string) {
	p.Group = group
}

func (p *KeycloakProvider) SetUserIDClaim(claim string) {
	p.UserIDClaim = claim
}

func (p *KeycloakProvider) checkGroupAccess(json *simplejson.Json) error {
	if p.Group != "" {
		var groups, err = json.Get("groups").Array()
		if err != nil {
			logger.Printf("groups not found %s", err)
			return err
		}

		var found = false
		for i := range groups {
			if groups[i].(string) == p.Group {
				return nil
			}
		}

		if !found {
			logger.Printf("group not found, access denied")
			return errors.New("group not found, access denied")
		}
	}
	return nil
}

func (p *KeycloakProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	json, err := requests.New(p.ValidateURL.String()).
		WithContext(ctx).
		SetHeader("Authorization", "Bearer "+s.AccessToken).
		Do().
		UnmarshalJSON()
	if err != nil {
		logger.Printf("failed making request %s", err)
		return "", err
	}

	if err := p.checkGroupAccess(json); err != nil {
		return "", err
	}

	if p.UserIDClaim != "" {
		return json.Get(p.UserIDClaim).String()
	}
	return json.Get(emailClaim).String()
}
