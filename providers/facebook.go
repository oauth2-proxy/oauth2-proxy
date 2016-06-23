package providers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/bitly/oauth2_proxy/api"
)

type FacebookProvider struct {
	*ProviderData
}

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

func getFacebookHeader(access_token string) http.Header {
	header := make(http.Header)
	header.Set("Accept", "application/json")
	header.Set("x-li-format", "json")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", access_token))
	return header
}

func (p *FacebookProvider) GetEmailAddress(s *SessionState) (string, error) {
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
	err = api.RequestJson(req, &r)
	if err != nil {
		return "", err
	}
	if r.Email == "" {
		return "", errors.New("no email")
	}
	return r.Email, nil
}

func (p *FacebookProvider) ValidateSessionState(s *SessionState) bool {
	return validateToken(p, s.AccessToken, getFacebookHeader(s.AccessToken))
}
