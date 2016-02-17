package providers

import (
	"encoding/json"
	"fmt"
	"strings"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

type GitHubProvider struct {
	*ProviderData
	Org  string
	Team string
}

func NewGitHubProvider(p *ProviderData) *GitHubProvider {
	p.ProviderName = "GitHub"
	if p.LoginURL == nil || p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   "github.com",
			Path:   "/login/oauth/authorize",
		}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   "github.com",
			Path:   "/login/oauth/access_token",
		}
	}
	if p.ValidateURL == nil || p.ValidateURL.String() == "" {
		p.ValidateURL = &url.URL{
			Scheme: "https",
			Host:   "api.github.com",
			Path:   "/user/emails",
		}
	}
	if p.Scope == "" {
		p.Scope = "user:email"
	}
	return &GitHubProvider{ProviderData: p}
}
func (p *GitHubProvider) SetOrgTeam(org, team string) {
	p.Org = org
	p.Team = team
	if org != "" || team != "" {
		p.Scope += " read:org"
	}
}

func (p *GitHubProvider) hasOrg(accessToken string) (bool, error) {
	// https://developer.github.com/v3/orgs/#list-your-organizations

	var orgs []struct {
		Login string `json:"login"`
	}

	params := url.Values{
		"access_token": {accessToken},
		"limit":        {"100"},
	}

	endpoint := p.ValidateURL.Scheme + "://"  + p.ValidateURL.Host + "/user/orgs?" + params.Encode()
	req, _ := http.NewRequest("GET", endpoint, nil)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return false, err
	}
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("got %d from %q %s", resp.StatusCode, endpoint, body)
	}

	if err := json.Unmarshal(body, &orgs); err != nil {
		return false, err
	}

	var presentOrgs []string
	for _, org := range orgs {
		if p.Org == org.Login {
			log.Printf("Found Github Organization: %q", org.Login)
			return true, nil
		}
		presentOrgs = append(presentOrgs, org.Login)
	}

	log.Printf("Missing Organization:%q in %v", p.Org, presentOrgs)
	return false, nil
}

func (p *GitHubProvider) hasOrgAndTeam(accessToken string) (bool, error) {
	// https://developer.github.com/v3/orgs/teams/#list-user-teams

	var teams []struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
		Org  struct {
			Login string `json:"login"`
		} `json:"organization"`
	}

	params := url.Values{
		"access_token": {accessToken},
		"limit":        {"100"},
	}

	endpoint := p.ValidateURL.Scheme + "://" + p.ValidateURL.Host + "/user/teams?" + params.Encode()
	req, _ := http.NewRequest("GET", endpoint, nil)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return false, err
	}
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("got %d from %q %s", resp.StatusCode, endpoint, body)
	}

	if err := json.Unmarshal(body, &teams); err != nil {
		return false, fmt.Errorf("%s unmarshaling %s", err, body)
	}

	var hasOrg bool
	presentOrgs := make(map[string]bool)
	var presentTeams []string
	for _, team := range teams {
		presentOrgs[team.Org.Login] = true
		if p.Org == team.Org.Login {
			hasOrg = true
			ts := strings.Split(p.Team, ",")
			for _, t := range ts {
				if t == team.Slug {
					log.Printf("Found Github Organization:%q Team:%q (Name:%q)", team.Org.Login, team.Slug, team.Name)
					return true, nil
				}
			}
			presentTeams = append(presentTeams, team.Slug)
		}
	}
	if hasOrg {
		log.Printf("Missing Team:%q from Org:%q in teams: %v", p.Team, p.Org, presentTeams)
	} else {
		var allOrgs []string
		for org, _ := range presentOrgs {
			allOrgs = append(allOrgs, org)
		}
		log.Printf("Missing Organization:%q in %#v", p.Org, allOrgs)
	}
	return false, nil
}

func (p *GitHubProvider) GetEmailAddress(s *SessionState) (string, error) {

	var emails []struct {
		Email   string `json:"email"`
		Primary bool   `json:"primary"`
	}

	// if we require an Org or Team, check that first
	if p.Org != "" {
		if p.Team != "" {
			if ok, err := p.hasOrgAndTeam(s.AccessToken); err != nil || !ok {
				return "", err
			}
		} else {
			if ok, err := p.hasOrg(s.AccessToken); err != nil || !ok {
				return "", err
			}
		}
	}

	params := url.Values{
		"access_token": {s.AccessToken},
	}
	endpoint := p.ValidateURL.Scheme + "://" + p.ValidateURL.Host + p.ValidateURL.Path + "?" + params.Encode()
	resp, err := http.DefaultClient.Get(endpoint)
	if err != nil {
		return "", err
	}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("got %d from %q %s", resp.StatusCode, endpoint, body)
	} else {
		log.Printf("got %d from %q %s", resp.StatusCode, endpoint, body)
	}

	if err := json.Unmarshal(body, &emails); err != nil {
		return "", fmt.Errorf("%s unmarshaling %s", err, body)
	}

	for _, email := range emails {
		if email.Primary {
			return email.Email, nil
		}
	}

	return "", nil
}
