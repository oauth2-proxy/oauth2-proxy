package providers

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/logger"
	"github.com/pusher/oauth2_proxy/pkg/requests"
)

// BitbucketProvider represents an Bitbucket based Identity Provider
type BitbucketProvider struct {
	*ProviderData
	Team       string
	Repository string
}

// NewBitbucketProvider initiates a new BitbucketProvider
func NewBitbucketProvider(p *ProviderData) *BitbucketProvider {
	p.ProviderName = "Bitbucket"
	if p.LoginURL == nil || p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   "bitbucket.org",
			Path:   "/site/oauth2/authorize",
		}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   "bitbucket.org",
			Path:   "/site/oauth2/access_token",
		}
	}
	if p.ValidateURL == nil || p.ValidateURL.String() == "" {
		p.ValidateURL = &url.URL{
			Scheme: "https",
			Host:   "api.bitbucket.org",
			Path:   "/2.0/user/emails",
		}
	}
	if p.Scope == "" {
		p.Scope = "email"
	}
	return &BitbucketProvider{ProviderData: p}
}

// SetTeam defines the Bitbucket team the user must be part of
func (p *BitbucketProvider) SetTeam(team string) {
	p.Team = team
	if !strings.Contains(p.Scope, "team") {
		p.Scope += " team"
	}
}

// SetRepository defines the repository the user must have access to
func (p *BitbucketProvider) SetRepository(repository string) {
	p.Repository = repository
	if !strings.Contains(p.Scope, "repository") {
		p.Scope += " repository"
	}
}

// GetEmailAddress returns the email of the authenticated user
func (p *BitbucketProvider) GetEmailAddress(s *sessions.SessionState) (string, error) {

	var emails struct {
		Values []struct {
			Email   string `json:"email"`
			Primary bool   `json:"is_primary"`
		}
	}
	var teams struct {
		Values []struct {
			Name string `json:"username"`
		}
	}
	var repositories struct {
		Values []struct {
			FullName string `json:"full_name"`
		}
	}
	req, err := http.NewRequest("GET",
		p.ValidateURL.String()+"?access_token="+s.AccessToken, nil)
	if err != nil {
		logger.Printf("failed building request %s", err)
		return "", err
	}
	err = requests.RequestJSON(req, &emails)
	if err != nil {
		logger.Printf("failed making request %s", err)
		return "", err
	}

	if p.Team != "" {
		teamURL := &url.URL{}
		*teamURL = *p.ValidateURL
		teamURL.Path = "/2.0/teams"
		req, err = http.NewRequest("GET",
			teamURL.String()+"?role=member&access_token="+s.AccessToken, nil)
		if err != nil {
			logger.Printf("failed building request %s", err)
			return "", err
		}
		err = requests.RequestJSON(req, &teams)
		if err != nil {
			logger.Printf("failed requesting teams membership %s", err)
			return "", err
		}
		var found = false
		for _, team := range teams.Values {
			if p.Team == team.Name {
				found = true
				break
			}
		}
		if found != true {
			logger.Print("team membership test failed, access denied")
			return "", nil
		}
	}

	if p.Repository != "" {
		repositoriesURL := &url.URL{}
		*repositoriesURL = *p.ValidateURL
		repositoriesURL.Path = "/2.0/repositories/" + strings.Split(p.Repository, "/")[0]
		req, err = http.NewRequest("GET",
			repositoriesURL.String()+"?role=contributor"+
				"&q=full_name="+url.QueryEscape("\""+p.Repository+"\"")+
				"&access_token="+s.AccessToken,
			nil)
		if err != nil {
			logger.Printf("failed building request %s", err)
			return "", err
		}
		err = requests.RequestJSON(req, &repositories)
		if err != nil {
			logger.Printf("failed checking repository access %s", err)
			return "", err
		}
		var found = false
		for _, repository := range repositories.Values {
			if p.Repository == repository.FullName {
				found = true
				break
			}
		}
		if found != true {
			logger.Print("repository access test failed, access denied")
			return "", nil
		}
	}

	for _, email := range emails.Values {
		if email.Primary {
			return email.Email, nil
		}
	}

	return "", nil
}
