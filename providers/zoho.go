package providers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/requests"
)

// ZohoProvider represents a Zoho based Identity Provider
type ZohoProvider struct {
	*ProviderData
}

// NewZohoProvider initiates a new ZohoProvider
func NewZohoProvider(p *ProviderData) *ZohoProvider {
	p.ProviderName = "Zoho"
	if p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{Scheme: "https",
			Host:     "accounts.zoho.com",
			Path:     "/oauth/v2/auth",
			RawQuery: "response_type=code&access_type=offline",
		}
	}
	if p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{Scheme: "https",
			Host: "accounts.zoho.com",
			Path: "/oauth/v2/token",
		}
	}
	if p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{Scheme: "https",
			Host: "accounts.zoho.com",
			Path: "/oauth/user/info",
		}
	}
	if p.ValidateURL.String() == "" {
		p.ValidateURL = p.ProfileURL
	}
	if p.Scope == "" {
		p.Scope = "ZohoProfile.userinfo.read,Aaaserver.profile.read"
	}
	return &ZohoProvider{ProviderData: p}
}

func getZohoHeader(accessToken string) http.Header {
	header := make(http.Header)
	header.Set("Content-Type", "application/json")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	return header
}

// GetEmailAddress returns the Account email address
func (p *ZohoProvider) GetEmailAddress(s *sessions.SessionState) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}
	req, err := http.NewRequest("GET", p.ProfileURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header = getZohoHeader(s.AccessToken)

	json, err := requests.Request(req)
	if err != nil {
		return "", err
	}

	email, err := json.GetPath("Email").String()
	if err != nil {
		return "", err
	}
	return email, nil
}

// ValidateSessionState validates the AccessToken
func (p *ZohoProvider) ValidateSessionState(s *sessions.SessionState) bool {
	return validateToken(p, s.AccessToken, getZohoHeader(s.AccessToken))
}
