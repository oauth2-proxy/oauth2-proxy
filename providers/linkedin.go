package providers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/requests"
)

// LinkedInProvider represents an LinkedIn based Identity Provider
type LinkedInProvider struct {
	*ProviderData
}

// NewLinkedInProvider initiates a new LinkedInProvider
func NewLinkedInProvider(p *ProviderData) *LinkedInProvider {
	p.ProviderName = "LinkedIn"
	if p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{Scheme: "https",
			Host: "www.linkedin.com",
			Path: "/uas/oauth2/authorization"}
	}
	if p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{Scheme: "https",
			Host: "www.linkedin.com",
			Path: "/uas/oauth2/accessToken"}
	}
	if p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{Scheme: "https",
			Host: "www.linkedin.com",
			Path: "/v1/people/~/email-address"}
	}
	if p.ValidateURL.String() == "" {
		p.ValidateURL = p.ProfileURL
	}
	if p.Scope == "" {
		p.Scope = "r_emailaddress r_basicprofile"
	}
	return &LinkedInProvider{ProviderData: p}
}

func getLinkedInHeader(accessToken string) http.Header {
	header := make(http.Header)
	header.Set("Accept", "application/json")
	header.Set("x-li-format", "json")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	return header
}

// GetEmailAddress returns the Account email address
func (p *LinkedInProvider) GetEmailAddress(s *sessions.SessionState) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}
	req, err := http.NewRequest("GET", p.ProfileURL.String()+"?format=json", nil)
	if err != nil {
		return "", err
	}
	req.Header = getLinkedInHeader(s.AccessToken)

	json, err := requests.Request(req)
	if err != nil {
		return "", err
	}

	email, err := json.String()
	if err != nil {
		return "", err
	}
	return email, nil
}

// ValidateSessionState validates the AccessToken
func (p *LinkedInProvider) ValidateSessionState(s *sessions.SessionState) bool {
	return validateToken(p, s.AccessToken, getLinkedInHeader(s.AccessToken))
}
