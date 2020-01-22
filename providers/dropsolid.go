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
type DropsolidProvider struct {
	*ProviderData
}

// NewDigitalOceanProvider initiates a new DigitalOceanProvider
func NewDropsolidProvider(p *ProviderData) *DropsolidProvider {
	p.ProviderName = "Dropsolid"
	if p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{Scheme: "https",
			Host: "platform.dropsolid.com",
			Path: "/oauth/authorize",
		}
	}
	if p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{Scheme: "https",
			Host: "platform.dropsolid.com",
			Path: "/oauth/token",
		}
	}
	if p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{Scheme: "https",
			Host: "platform.dropsolid.com",
			Path: "/oauth/user.info",
		}
	}
	if p.Scope == "" {
		p.Scope = "openid"
	}
	return &DropsolidProvider{ProviderData: p}
}

func getDropsolidHeader(accessToken string) http.Header {
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	return header
}

// GetUserName returns the Account user name
func (p *DropsolidProvider) GetUserName(s *sessions.SessionState) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}

	req, err := http.NewRequest("GET", p.ProfileURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header = getDropsolidHeader(s.AccessToken)

	json, err := requests.Request(req)
	if err != nil {
		return "", err
	}

	userId, err := json.GetPath("sub").String()

	return userId, nil
}


// GetEmailAddress returns the Account email address
func (p *DropsolidProvider) GetEmailAddress(s *sessions.SessionState) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}
	req, err := http.NewRequest("GET", p.ProfileURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header = getDropsolidHeader(s.AccessToken)

	json, err := requests.Request(req)
	if err != nil {
		return "", err
	}

	email, err := json.GetPath("email").String()
	if err != nil {
		return "", err
	}
	return email, nil
}

// ValidateSessionState validates the AccessToken
func (p *DropsolidProvider) ValidateSessionState(s *sessions.SessionState) bool {
	return validateToken(p, s.AccessToken, getDropsolidHeader(s.AccessToken))
}
