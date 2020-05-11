package providers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/requests"
)

// FacebookProvider represents an Facebook based Identity Provider
type FacebookProvider struct {
	*ProviderData
}

var _ Provider = (*FacebookProvider)(nil)

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
func (p *FacebookProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}
	req, err := http.NewRequestWithContext(ctx, "GET", p.ProfileURL.String()+"?fields=name,email", nil)
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
func (p *FacebookProvider) ValidateSessionState(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, getFacebookHeader(s.AccessToken))
}
