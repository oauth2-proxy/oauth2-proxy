package providers

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/bitly/go-simplejson"
	"github.com/pusher/oauth2_proxy/api"
)

// GitLabProvider represents an GitLab based Identity Provider
type GitLabProvider struct {
	*ProviderData
	Group        string
	EmailDomains []string
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
			Path:   "/api/v4",
		}
	}
	p.Scope += " read_user"
	return &GitLabProvider{ProviderData: p}
}

// GetEmailAddress returns the Account email address
func (p *GitLabProvider) GetEmailAddress(s *SessionState) (string, error) {
	if p.Group != "" {
		groupsJSON, groupsJSONError := data(p.ValidateURL.String()+"/groups?access_token="+s.AccessToken, s)
		if groupsJSONError != nil {
			return "", groupsJSONError
		}
		groupsValid := false
		for i := range groupsJSON.MustArray() {
			group, groupJSONError := groupsJSON.GetIndex(i).Get("name").String()
			if groupJSONError == nil {
				groupsValid = groupsValid || (strings.ToLower(group) == p.Group)
			}
		}
		if !groupsValid {
			return "", fmt.Errorf("user has no access to group %s", p.Group)
		}
	}

	primaryUserEmailJSON, primaryUserEmailJSONError := data(p.ValidateURL.String()+"/user?access_token="+s.AccessToken, s)
	if primaryUserEmailJSONError != nil {
		return "", primaryUserEmailJSONError
	}
	primaryUserEmail, primaryUserEmailError := primaryUserEmailJSON.Get("email").String()
	if primaryUserEmailError != nil {
		return "", primaryUserEmailError
	}

	if (len(p.EmailDomains) == 0) || (p.EmailDomains[0] == "*") {
		return primaryUserEmail, nil
	}

	userEmailCandidates := []string{
		primaryUserEmail,
	}
	secondaryUserEmailsJSON, secondaryUserEmailsJSONError := data(p.ValidateURL.String()+"/user/emails?access_token="+s.AccessToken, s)
	if secondaryUserEmailsJSONError != nil {
		return "", secondaryUserEmailsJSONError
	}
	for i := range secondaryUserEmailsJSON.MustArray() {
		secondaryUserEmail, secondaryUserEmailError := secondaryUserEmailsJSON.GetIndex(i).Get("email").String()
		if secondaryUserEmailError == nil {
			userEmailCandidates = append(userEmailCandidates, secondaryUserEmail)
		}
	}
	for _, userEmailCandidate := range userEmailCandidates {
		for _, domain := range p.EmailDomains {
			if strings.HasSuffix(userEmailCandidate, domain) {
				return userEmailCandidate, nil
			}
		}
	}
	return userEmailCandidates[0], nil
}

// SetGroup adds api scope to the oidc scopes
func (p *GitLabProvider) SetGroup(group string) {
	p.Group = strings.ToLower(group)
	p.Scope += " api"
}

// SetEmailDomains to filter emails for
func (p *GitLabProvider) SetEmailDomains(domains []string) {
	p.EmailDomains = domains
}

func data(url string, s *SessionState) (*simplejson.Json, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("failed building request %s", err)
		return nil, err
	}
	json, err := api.Request(req)
	if err != nil {
		log.Printf("failed making request %s", err)
		return nil, err
	}
	return json, nil
}
