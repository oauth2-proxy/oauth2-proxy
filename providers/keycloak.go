package providers

import (
	"context"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/requests"
)

type KeycloakProvider struct {
	*ProviderData
	Group string
}

var _ Provider = (*KeycloakProvider)(nil)

func NewKeycloakProvider(p *ProviderData) *KeycloakProvider {
	p.ProviderName = "Keycloak"
	if p.LoginURL == nil || p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   "keycloak.org",
			Path:   "/oauth/authorize",
		}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   "keycloak.org",
			Path:   "/oauth/token",
		}
	}
	if p.ValidateURL == nil || p.ValidateURL.String() == "" {
		p.ValidateURL = &url.URL{
			Scheme: "https",
			Host:   "keycloak.org",
			Path:   "/api/v3/user",
		}
	}
	if p.Scope == "" {
		p.Scope = "api"
	}
	return &KeycloakProvider{ProviderData: p}
}

func (p *KeycloakProvider) SetGroup(group string) {
	p.Group = group
}

func (p *KeycloakProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	json, err := requests.New(p.ValidateURL.String()).
		WithContext(ctx).
		SetHeader("Authorization", "Bearer "+s.AccessToken).
		UnmarshalJSON()
	if err != nil {
		logger.Printf("failed making request %s", err)
		return "", err
	}

	if p.Group != "" {
		var groups, err = json.Get("groups").Array()
		if err != nil {
			logger.Printf("groups not found %s", err)
			return "", err
		}

		var found = false
		for i := range groups {
			if groups[i].(string) == p.Group {
				found = true
				break
			}
		}

		if !found {
			logger.Printf("group not found, access denied")
			return "", nil
		}
	}

	return json.Get("email").String()
}
