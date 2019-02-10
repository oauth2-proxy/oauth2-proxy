package providers

import (
	"net/http"
	"net/url"

	"github.com/pusher/oauth2_proxy/api"
	"github.com/pusher/oauth2_proxy/logger"
)

// GitLabProvider represents an GitLab based Identity Provider
type GitLabProvider struct {
	*ProviderData
}

// NewGitLabProvider initiates a new GitLabProvider
func NewGitLabProvider(p *ProviderData) *GitLabProvider {
	p.ProviderName = "GitLab"
	if p.LoginURL == nil || p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   "gitlab.com",
			Path:   "/oauth/authorize",
		}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   "gitlab.com",
			Path:   "/oauth/token",
		}
	}
	if p.ValidateURL == nil || p.ValidateURL.String() == "" {
		p.ValidateURL = &url.URL{
			Scheme: "https",
			Host:   "gitlab.com",
			Path:   "/api/v4/user",
		}
	}
	if p.Scope == "" {
		p.Scope = "read_user"
	}
	return &GitLabProvider{ProviderData: p}
}

// GetEmailAddress returns the Account email address
func (p *GitLabProvider) GetEmailAddress(s *SessionState) (string, error) {

	req, err := http.NewRequest("GET",
		p.ValidateURL.String()+"?access_token="+s.AccessToken, nil)
	if err != nil {
		logger.Printf("failed building request %s", err)
		return "", err
	}
	json, err := api.Request(req)
	if err != nil {
		logger.Printf("failed making request %s", err)
		return "", err
	}
	return json.Get("email").String()
}
