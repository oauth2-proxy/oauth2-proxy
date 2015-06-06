package providers

import (
	"encoding/json"
	"io/ioutil"
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
	if p.LoginUrl.String() == "" {
		p.LoginUrl = &url.URL{
			Scheme: "https",
			Host:   "github.com",
			Path:   "/login/oauth/authorize",
		}
	}
	if p.RedeemUrl.String() == "" {
		p.RedeemUrl = &url.URL{
			Scheme: "https",
			Host:   "github.com",
			Path:   "/login/oauth/access_token",
		}
	}
	if p.ValidateUrl.String() == "" {
		p.ValidateUrl = &url.URL{
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
		"limit": {"100"},
	}

	req, _ := http.NewRequest("GET", "https://api.github.com/user/orgs?"+params.Encode(), nil)
	req.Header.Set("Accept", "application/vnd.github.moondragon+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return false, err
	}

	if err := json.Unmarshal(body, &orgs); err != nil {
		return false, err
	}

	for _, org := range orgs {
		if p.Org == org.Login {
			return true, nil
		}
	}
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
		"limit": {"100"},
	}

	req, _ := http.NewRequest("GET", "https://api.github.com/user/teams?"+params.Encode(), nil)
	req.Header.Set("Accept", "application/vnd.github.moondragon+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return false, err
	}

	if err := json.Unmarshal(body, &teams); err != nil {
		return false, err
	}

	for _, team := range teams {
		if p.Org == team.Org.Login {
			if p.Team == "" || p.Team == team.Slug {
				return true, nil
			}
		}
	}
	return false, nil
}

func (p *GitHubProvider) GetEmailAddress(body []byte, access_token string) (string, error) {

	var emails []struct {
		Email   string `json:"email"`
		Primary bool   `json:"primary"`
	}


	// if we require an Org or Team, check that first
	if p.Org != "" {
		if p.Team != "" {
			if ok, err := p.hasOrgAndTeam(access_token); err != nil || !ok {
				return "", err
			}
		} else {
			if ok, err := p.hasOrg(access_token); err != nil || !ok {
				return "", err
			}
		}
	}

	params := url.Values{
		"access_token": {access_token},
	}
	resp, err := http.DefaultClient.Get("https://api.github.com/user/emails?" + params.Encode())
	if err != nil {
		return "", err
	}
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", err
	}

	if err := json.Unmarshal(body, &emails); err != nil {
		return "", err
	}

	for _, email := range emails {
		if email.Primary {
			return email.Email, nil
		}
	}

	return "", nil
}

func (p *GitHubProvider) ValidateToken(access_token string) bool {
	return validateToken(p, access_token, nil)
}
