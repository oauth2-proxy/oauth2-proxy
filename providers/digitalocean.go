package providers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/requests"
)

// DigitalOceanProvider represents a DigitalOcean based Identity Provider
type DigitalOceanProvider struct {
	*ProviderData
}

// NewDigitalOceanProvider initiates a new DigitalOceanProvider
func NewDigitalOceanProvider(p *ProviderData) *DigitalOceanProvider {
	p.ProviderName = "DigitalOcean"
	if p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{Scheme: "https",
			Host: "cloud.digitalocean.com",
			Path: "/v1/oauth/authorize",
		}
	}
	if p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{Scheme: "https",
			Host: "cloud.digitalocean.com",
			Path: "/v1/oauth/token",
		}
	}
	if p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{Scheme: "https",
			Host: "api.digitalocean.com",
			Path: "/v2/account",
		}
	}
	if p.ValidateURL.String() == "" {
		p.ValidateURL = p.ProfileURL
	}
	if p.Scope == "" {
		p.Scope = "read"
	}
	return &DigitalOceanProvider{ProviderData: p}
}

func getDigitalOceanHeader(accessToken string) http.Header {
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	return header
}

// GetEmailAddress returns the Account email address
func (p *DigitalOceanProvider) GetEmailAddress(s *sessions.SessionState) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}
	req, err := http.NewRequest("GET", p.ProfileURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header = getDigitalOceanHeader(s.AccessToken)

	json, err := requests.Request(req)
	if err != nil {
		return "", err
	}

	email, err := json.GetPath("account", "email").String()
	if err != nil {
		return "", err
	}
	return email, nil
}

// ValidateSessionState validates the AccessToken
func (p *DigitalOceanProvider) ValidateSessionState(s *sessions.SessionState) bool {
	return validateToken(p, s.AccessToken, getDigitalOceanHeader(s.AccessToken))
}
