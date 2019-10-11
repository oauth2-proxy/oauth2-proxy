package providers

import (
	"net/http"
	"net/url"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/logger"
	"github.com/pusher/oauth2_proxy/pkg/requests"
)

type KeycloakProvider struct {
	*ProviderData
	Group string
}

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

func (p *KeycloakProvider) GetEmailAddress(s *sessions.SessionState) (string, error) {

	req, err := http.NewRequest("GET", p.ValidateURL.String(), nil)
	req.Header.Set("Authorization", "Bearer "+s.AccessToken)
	if err != nil {
		logger.Printf("failed building request %s", err)
		return "", err
	}
	json, err := requests.Request(req)
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

		if found != true {
			logger.Printf("group not found, access denied")
			return "", nil
		}
	}

	return json.Get("email").String()
}
