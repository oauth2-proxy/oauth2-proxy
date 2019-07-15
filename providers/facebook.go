package providers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/requests"
)

// FacebookProvider represents an Facebook based Identity Provider
type FacebookProvider struct {
	*ProviderData
}

// NewFacebookProvider initiates a new FacebookProvider
func NewFacebookProvider(p *ProviderData) *FacebookProvider {
	p.ProviderName = "Facebook"
	if p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{Scheme: "https",
			Host: "www.facebook.com",
			Path: "/v2.5/dialog/oauth",
			// ?granted_scopes=true
		}
	}
	if p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{Scheme: "https",
			Host: "graph.facebook.com",
			Path: "/v2.5/oauth/access_token",
		}
	}
	if p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{Scheme: "https",
			Host: "graph.facebook.com",
			Path: "/v2.5/me",
		}
	}
	if p.ValidateURL.String() == "" {
		p.ValidateURL = p.ProfileURL
	}
	if p.Scope == "" {
		p.Scope = "public_profile email"
	}
	return &FacebookProvider{ProviderData: p}
}

func getFacebookHeader(accessToken string) http.Header {
	header := make(http.Header)
	header.Set("Accept", "application/json")
	header.Set("x-li-format", "json")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	return header
}

// GetEmailAddress returns the Account email address
func (p *FacebookProvider) GetEmailAddress(s *sessions.SessionState) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}
	req, err := http.NewRequest("GET", p.ProfileURL.String()+"?fields=name,email", nil)
	if err != nil {
		return "", err
	}
	req.Header = getFacebookHeader(s.AccessToken)

	type result struct {
		Email string
	}
	var r result
	err = requests.RequestJSON(req, &r)
	if err != nil {
		return "", err
	}
	if r.Email == "" {
		return "", errors.New("no email")
	}
	return r.Email, nil
}

// ValidateSessionState validates the AccessToken
func (p *FacebookProvider) ValidateSessionState(s *sessions.SessionState) bool {
	return validateToken(p, s.AccessToken, getFacebookHeader(s.AccessToken))
}
