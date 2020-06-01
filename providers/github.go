package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
)

// GitHubProvider represents an GitHub based Identity Provider
type GitHubProvider struct {
	*ProviderData
	Org   string
	Team  string
	Repo  string
	Token string
	Users []string
}

var _ Provider = (*GitHubProvider)(nil)

// NewGitHubProvider initiates a new GitHubProvider
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
	// ValidationURL is the API Base URL
	if p.ValidateURL == nil || p.ValidateURL.String() == "" {
		p.ValidateURL = &url.URL{
			Scheme: "https",
			Host:   "api.github.com",
			Path:   "/",
		}
	}
	if p.Scope == "" {
		p.Scope = "user:email"
	}
	return &GitHubProvider{ProviderData: p}
}

func getGitHubHeader(accessToken string) http.Header {
	header := make(http.Header)
	header.Set("Accept", "application/vnd.github.v3+json")
	header.Set("Authorization", fmt.Sprintf("token %s", accessToken))
	return header
}

// SetOrgTeam adds GitHub org reading parameters to the OAuth2 scope
func (p *GitHubProvider) SetOrgTeam(org, team string) {
	p.Org = org
	p.Team = team
	if org != "" || team != "" {
		p.Scope += " read:org"
	}
}

// SetRepo configures the target repository and optional token to use
func (p *GitHubProvider) SetRepo(repo, token string) {
	p.Repo = repo
	p.Token = token
}

// SetUsers configures allowed usernames
func (p *GitHubProvider) SetUsers(users []string) {
	p.Users = users
}

func (p *GitHubProvider) hasOrg(ctx context.Context, accessToken string) (bool, error) {
	// https://developer.github.com/v3/orgs/#list-your-organizations

	var orgs []struct {
		Login string `json:"login"`
	}

	type orgsPage []struct {
		Login string `json:"login"`
	}

	pn := 1
	for {
		params := url.Values{
			"per_page": {"100"},
			"page":     {strconv.Itoa(pn)},
		}

		endpoint := &url.URL{
			Scheme:   p.ValidateURL.Scheme,
			Host:     p.ValidateURL.Host,
			Path:     path.Join(p.ValidateURL.Path, "/user/orgs"),
			RawQuery: params.Encode(),
		}
		req, _ := http.NewRequestWithContext(ctx, "GET", endpoint.String(), nil)
		req.Header = getGitHubHeader(accessToken)
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
			return false, fmt.Errorf(
				"got %d from %q %s", resp.StatusCode, endpoint.String(), body)
		}

		var op orgsPage
		if err := json.Unmarshal(body, &op); err != nil {
			return false, err
		}
		if len(op) == 0 {
			break
		}

		orgs = append(orgs, op...)
		pn++
	}

	presentOrgs := make([]string, 0, len(orgs))
	for _, org := range orgs {
		if p.Org == org.Login {
			logger.Printf("Found Github Organization: %q", org.Login)
			return true, nil
		}
		presentOrgs = append(presentOrgs, org.Login)
	}

	logger.Printf("Missing Organization:%q in %v", p.Org, presentOrgs)
	return false, nil
}

func (p *GitHubProvider) hasOrgAndTeam(ctx context.Context, accessToken string) (bool, error) {
	// https://developer.github.com/v3/orgs/teams/#list-user-teams

	var teams []struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
		Org  struct {
			Login string `json:"login"`
		} `json:"organization"`
	}

	type teamsPage []struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
		Org  struct {
			Login string `json:"login"`
		} `json:"organization"`
	}

	pn := 1
	last := 0
	for {
		params := url.Values{
			"per_page": {"100"},
			"page":     {strconv.Itoa(pn)},
		}

		endpoint := &url.URL{
			Scheme:   p.ValidateURL.Scheme,
			Host:     p.ValidateURL.Host,
			Path:     path.Join(p.ValidateURL.Path, "/user/teams"),
			RawQuery: params.Encode(),
		}

		req, _ := http.NewRequestWithContext(ctx, "GET", endpoint.String(), nil)
		req.Header = getGitHubHeader(accessToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false, err
		}

		if last == 0 {
			// link header may not be obtained
			// When paging is not required and all data can be retrieved with a single call

			// Conditions for obtaining the link header.
			// 1. When paging is required (Example: When the data size is 100 and the page size is 99 or less)
			// 2. When it exceeds the paging frame (Example: When there is only 10 records but the second page is called with a page size of 100)

			// link header at not last page
			// <https://api.github.com/user/teams?page=1&per_page=100>; rel="prev", <https://api.github.com/user/teams?page=1&per_page=100>; rel="last", <https://api.github.com/user/teams?page=1&per_page=100>; rel="first"
			// link header at last page (doesn't exist last info)
			// <https://api.github.com/user/teams?page=3&per_page=10>; rel="prev", <https://api.github.com/user/teams?page=1&per_page=10>; rel="first"

			link := resp.Header.Get("Link")
			rep1 := regexp.MustCompile(`(?s).*\<https://api.github.com/user/teams\?page=(.)&per_page=[0-9]+\>; rel="last".*`)
			i, converr := strconv.Atoi(rep1.ReplaceAllString(link, "$1"))

			// If the last page cannot be taken from the link in the http header, the last variable remains zero
			if converr == nil {
				last = i
			}
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			resp.Body.Close()
			return false, err
		}
		resp.Body.Close()

		if resp.StatusCode != 200 {
			return false, fmt.Errorf(
				"got %d from %q %s", resp.StatusCode, endpoint.String(), body)
		}

		var tp teamsPage
		if err := json.Unmarshal(body, &tp); err != nil {
			return false, fmt.Errorf("%s unmarshaling %s", err, body)
		}
		if len(tp) == 0 {
			break
		}

		teams = append(teams, tp...)

		if pn == last {
			break
		}
		if last == 0 {
			break
		}

		pn++
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
					logger.Printf("Found Github Organization:%q Team:%q (Name:%q)", team.Org.Login, team.Slug, team.Name)
					return true, nil
				}
			}
			presentTeams = append(presentTeams, team.Slug)
		}
	}
	if hasOrg {
		logger.Printf("Missing Team:%q from Org:%q in teams: %v", p.Team, p.Org, presentTeams)
	} else {
		var allOrgs []string
		for org := range presentOrgs {
			allOrgs = append(allOrgs, org)
		}
		logger.Printf("Missing Organization:%q in %#v", p.Org, allOrgs)
	}
	return false, nil
}

func (p *GitHubProvider) hasRepo(ctx context.Context, accessToken string) (bool, error) {
	// https://developer.github.com/v3/repos/#get-a-repository

	type permissions struct {
		Pull bool `json:"pull"`
		Push bool `json:"push"`
	}

	type repository struct {
		Permissions permissions `json:"permissions"`
		Private     bool        `json:"private"`
	}

	endpoint := &url.URL{
		Scheme: p.ValidateURL.Scheme,
		Host:   p.ValidateURL.Host,
		Path:   path.Join(p.ValidateURL.Path, "/repo/", p.Repo),
	}

	req, _ := http.NewRequestWithContext(ctx, "GET", endpoint.String(), nil)
	req.Header = getGitHubHeader(accessToken)
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
		return false, fmt.Errorf(
			"got %d from %q %s", resp.StatusCode, endpoint.String(), body)
	}

	var repo repository
	if err := json.Unmarshal(body, &repo); err != nil {
		return false, err
	}

	// Every user can implicitly pull from a public repo, so only grant access
	// if they have push access or the repo is private and they can pull
	return repo.Permissions.Push || (repo.Private && repo.Permissions.Pull), nil
}

func (p *GitHubProvider) hasUser(ctx context.Context, accessToken string) (bool, error) {
	// https://developer.github.com/v3/users/#get-the-authenticated-user

	var user struct {
		Login string `json:"login"`
		Email string `json:"email"`
	}

	endpoint := &url.URL{
		Scheme: p.ValidateURL.Scheme,
		Host:   p.ValidateURL.Host,
		Path:   path.Join(p.ValidateURL.Path, "/user"),
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", endpoint.String(), nil)
	req.Header = getGitHubHeader(accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, err
	}
	if resp.StatusCode != 200 {
		return false, fmt.Errorf("got %d from %q %s",
			resp.StatusCode, stripToken(endpoint.String()), body)
	}

	if err := json.Unmarshal(body, &user); err != nil {
		return false, err
	}

	if p.isVerifiedUser(user.Login) {
		return true, nil
	}
	return false, nil
}

func (p *GitHubProvider) isCollaborator(ctx context.Context, username, accessToken string) (bool, error) {
	//https://developer.github.com/v3/repos/collaborators/#check-if-a-user-is-a-collaborator

	endpoint := &url.URL{
		Scheme: p.ValidateURL.Scheme,
		Host:   p.ValidateURL.Host,
		Path:   path.Join(p.ValidateURL.Path, "/repos/", p.Repo, "/collaborators/", username),
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", endpoint.String(), nil)
	req.Header = getGitHubHeader(accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return false, err
	}

	if resp.StatusCode != 204 {
		return false, fmt.Errorf("got %d from %q %s",
			resp.StatusCode, endpoint.String(), body)
	}

	logger.Printf("got %d from %q %s", resp.StatusCode, endpoint.String(), body)

	return true, nil
}

// GetEmailAddress returns the Account email address
func (p *GitHubProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}

	// If usernames are set, check that first
	verifiedUser := false
	if len(p.Users) > 0 {
		var err error
		verifiedUser, err = p.hasUser(ctx, s.AccessToken)
		if err != nil {
			return "", err
		}
		// org and repository options are not configured
		if !verifiedUser && p.Org == "" && p.Repo == "" {
			return "", errors.New("missing github user")
		}
	}
	// If a user is verified by username options, skip the following restrictions
	if !verifiedUser {
		if p.Org != "" {
			if p.Team != "" {
				if ok, err := p.hasOrgAndTeam(ctx, s.AccessToken); err != nil || !ok {
					return "", err
				}
			} else {
				if ok, err := p.hasOrg(ctx, s.AccessToken); err != nil || !ok {
					return "", err
				}
			}
		} else if p.Repo != "" && p.Token == "" { // If we have a token we'll do the collaborator check in GetUserName
			if ok, err := p.hasRepo(ctx, s.AccessToken); err != nil || !ok {
				return "", err
			}
		}
	}

	endpoint := &url.URL{
		Scheme: p.ValidateURL.Scheme,
		Host:   p.ValidateURL.Host,
		Path:   path.Join(p.ValidateURL.Path, "/user/emails"),
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", endpoint.String(), nil)
	req.Header = getGitHubHeader(s.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("got %d from %q %s",
			resp.StatusCode, endpoint.String(), body)
	}

	logger.Printf("got %d from %q %s", resp.StatusCode, endpoint.String(), body)

	if err := json.Unmarshal(body, &emails); err != nil {
		return "", fmt.Errorf("%s unmarshaling %s", err, body)
	}

	returnEmail := ""
	for _, email := range emails {
		if email.Verified {
			returnEmail = email.Email
			if email.Primary {
				return returnEmail, nil
			}
		}
	}

	return returnEmail, nil
}

// GetUserName returns the Account user name
func (p *GitHubProvider) GetUserName(ctx context.Context, s *sessions.SessionState) (string, error) {
	var user struct {
		Login string `json:"login"`
		Email string `json:"email"`
	}

	endpoint := &url.URL{
		Scheme: p.ValidateURL.Scheme,
		Host:   p.ValidateURL.Host,
		Path:   path.Join(p.ValidateURL.Path, "/user"),
	}

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint.String(), nil)
	if err != nil {
		return "", fmt.Errorf("could not create new GET request: %v", err)
	}

	req.Header = getGitHubHeader(s.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}

	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("got %d from %q %s",
			resp.StatusCode, endpoint.String(), body)
	}

	logger.Printf("got %d from %q %s", resp.StatusCode, endpoint.String(), body)

	if err := json.Unmarshal(body, &user); err != nil {
		return "", fmt.Errorf("%s unmarshaling %s", err, body)
	}

	// Now that we have the username we can check collaborator status
	if !p.isVerifiedUser(user.Login) && p.Org == "" && p.Repo != "" && p.Token != "" {
		if ok, err := p.isCollaborator(ctx, user.Login, p.Token); err != nil || !ok {
			return "", err
		}
	}

	return user.Login, nil
}

// ValidateSessionState validates the AccessToken
func (p *GitHubProvider) ValidateSessionState(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, getGitHubHeader(s.AccessToken))
}

// isVerifiedUser
func (p *GitHubProvider) isVerifiedUser(username string) bool {
	for _, u := range p.Users {
		if username == u {
			return true
		}
	}
	return false
}
