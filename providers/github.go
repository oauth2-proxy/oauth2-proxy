package providers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
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

const (
	githubProviderName = "GitHub"
	githubDefaultScope = "user:email read:org"
)

var (
	// Default Login URL for GitHub.
	// Pre-parsed URL of https://github.org/login/oauth/authorize.
	githubDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "github.com",
		Path:   "/login/oauth/authorize",
	}

	// Default Redeem URL for GitHub.
	// Pre-parsed URL of https://github.org/login/oauth/access_token.
	githubDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "github.com",
		Path:   "/login/oauth/access_token",
	}

	// Default Validation URL for GitHub.
	// ValidationURL is the API Base URL.
	// Other API requests are based off of this (eg to fetch users/groups).
	// Pre-parsed URL of https://api.github.com/.
	githubDefaultValidateURL = &url.URL{
		Scheme: "https",
		Host:   "api.github.com",
		Path:   "/",
	}
)

// NewGitHubProvider initiates a new GitHubProvider
func NewGitHubProvider(p *ProviderData, opts options.GitHubOptions) *GitHubProvider {
	p.setProviderDefaults(providerDefaults{
		name:        githubProviderName,
		loginURL:    githubDefaultLoginURL,
		redeemURL:   githubDefaultRedeemURL,
		profileURL:  nil,
		validateURL: githubDefaultValidateURL,
		scope:       githubDefaultScope,
	})

	provider := &GitHubProvider{ProviderData: p}

	provider.setOrgTeam(opts.Org, opts.Team)
	provider.setRepo(opts.Repo, opts.Token)
	provider.setUsers(opts.Users)
	return provider
}

func makeGitHubHeader(accessToken string) http.Header {
	// extra headers required by the GitHub API when making authenticated requests
	extraHeaders := map[string]string{
		acceptHeader: "application/vnd.github.v3+json",
	}
	return makeAuthorizationHeader(tokenTypeToken, accessToken, extraHeaders)
}

// setOrgTeam adds GitHub org reading parameters to the OAuth2 scope
func (p *GitHubProvider) setOrgTeam(org, team string) {
	p.Org = org
	p.Team = team
}

// setRepo configures the target repository and optional token to use
func (p *GitHubProvider) setRepo(repo, token string) {
	p.Repo = repo
	p.Token = token
}

// setUsers configures allowed usernames
func (p *GitHubProvider) setUsers(users []string) {
	p.Users = users
}

// EnrichSession updates the User & Email after the initial Redeem
func (p *GitHubProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	// Construct user info JSON from multiple GitHub API endpoints to have a more detailed session state
	err := p.getOrgAndTeam(ctx, s)
	if err != nil {
		return err
	}

	err = p.checkRestrictions(ctx, s)
	if err != nil {
		return err
	}

	err = p.getEmail(ctx, s)
	if err != nil {
		return err
	}

	return p.getUser(ctx, s)
}

// ValidateSession validates the AccessToken
func (p *GitHubProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeGitHubHeader(s.AccessToken))
}

func (p *GitHubProvider) hasOrg(ctx context.Context, s *sessions.SessionState) bool {
	// https://developer.github.com/v3/orgs/#list-your-organizations
	var orgs []string

	for _, group := range s.Groups {
		if !strings.Contains(group, ":") {
			orgs = append(orgs, group)
		}
	}

	presentOrgs := make([]string, 0, len(orgs))
	for _, org := range orgs {
		if p.Org == org {
			logger.Printf("Found Github Organization: %q", org)
			return true
		}
		presentOrgs = append(presentOrgs, org)
	}

	logger.Printf("Missing Organization:%q in %v", p.Org, presentOrgs)
	return false
}

func (p *GitHubProvider) hasOrgAndTeam(ctx context.Context, s *sessions.SessionState) bool {
	type orgTeam struct {
		Org  string `json:"org"`
		Team string `json:"team"`
	}

	var presentOrgTeams []orgTeam

	for _, group := range s.Groups {
		if strings.Contains(group, ":") {
			ot := strings.Split(group, ":")
			presentOrgTeams = append(presentOrgTeams, orgTeam{ot[0], ot[1]})
		}
	}

	var hasOrg bool
	var presentTeams []string
	presentOrgs := make(map[string]bool)

	for _, ot := range presentOrgTeams {
		presentOrgs[ot.Org] = true

		if p.Org == ot.Org {
			hasOrg = true
			ts := strings.Split(p.Team, ",")
			for _, t := range ts {
				if t == ot.Team {
					logger.Printf("Found Github Organization/Team: %q/%q", ot.Org, ot.Team)
					return true
				}
			}
			presentTeams = append(presentTeams, ot.Team)
		}
	}
	if hasOrg {
		logger.Printf("Missing Team: (%q) from Org: (%q) in teams: %v", p.Team, p.Org, presentTeams)
	} else {
		var allOrgs []string
		for org := range presentOrgs {
			allOrgs = append(allOrgs, org)
		}
		logger.Printf("Missing Organization:%q in %#v", p.Org, allOrgs)
	}
	return false
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
		Path:   path.Join(p.ValidateURL.Path, "/repos/", p.Repo),
	}

	var repo repository
	err := requests.New(endpoint.String()).
		WithContext(ctx).
		WithHeaders(makeGitHubHeader(accessToken)).
		Do().
		UnmarshalInto(&repo)
	if err != nil {
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

	err := requests.New(endpoint.String()).
		WithContext(ctx).
		WithHeaders(makeGitHubHeader(accessToken)).
		Do().
		UnmarshalInto(&user)
	if err != nil {
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
	result := requests.New(endpoint.String()).
		WithContext(ctx).
		WithHeaders(makeGitHubHeader(accessToken)).
		Do()
	if result.Error() != nil {
		return false, result.Error()
	}

	if result.StatusCode() != 204 {
		return false, fmt.Errorf("got %d from %q %s",
			result.StatusCode(), endpoint.String(), result.Body())
	}

	logger.Printf("got %d from %q %s", result.StatusCode(), endpoint.String(), result.Body())

	return true, nil
}

// getEmail updates the SessionState Email
func (p *GitHubProvider) getEmail(ctx context.Context, s *sessions.SessionState) error {

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}

	endpoint := &url.URL{
		Scheme: p.ValidateURL.Scheme,
		Host:   p.ValidateURL.Host,
		Path:   path.Join(p.ValidateURL.Path, "/user/emails"),
	}
	err := requests.New(endpoint.String()).
		WithContext(ctx).
		WithHeaders(makeGitHubHeader(s.AccessToken)).
		Do().
		UnmarshalInto(&emails)
	if err != nil {
		return err
	}

	for _, email := range emails {
		if email.Verified {
			if email.Primary {
				s.Email = email.Email
				return nil
			}
		}
	}

	return nil
}

// getUser updates the SessionState User
func (p *GitHubProvider) getUser(ctx context.Context, s *sessions.SessionState) error {
	var user struct {
		Login string `json:"login"`
		Email string `json:"email"`
	}

	endpoint := &url.URL{
		Scheme: p.ValidateURL.Scheme,
		Host:   p.ValidateURL.Host,
		Path:   path.Join(p.ValidateURL.Path, "/user"),
	}

	err := requests.New(endpoint.String()).
		WithContext(ctx).
		WithHeaders(makeGitHubHeader(s.AccessToken)).
		Do().
		UnmarshalInto(&user)
	if err != nil {
		return err
	}

	// Now that we have the username we can check collaborator status
	if !p.isVerifiedUser(user.Login) && p.Org == "" && p.Repo != "" && p.Token != "" {
		if ok, err := p.isCollaborator(ctx, user.Login, p.Token); err != nil || !ok {
			return err
		}
	}

	s.User = user.Login
	return nil
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

func (p *GitHubProvider) checkRestrictions(ctx context.Context, s *sessions.SessionState) error {
	if ok, err := p.checkUserRestriction(ctx, s); err != nil || !ok {
		return err
	}

	var err error

	// If a user is verified by username options, skip the following restrictions
	if p.Org != "" {
		if p.Team != "" {
			if ok := p.hasOrgAndTeam(ctx, s); !ok {
				return err
			}
		} else {
			if ok := p.hasOrg(ctx, s); !ok {
				return err
			}
		}
	} else if p.Repo != "" && p.Token == "" { // If we have a token we'll do the collaborator check in GetUserName
		if ok, err := p.hasRepo(ctx, s.AccessToken); err != nil || !ok {
			return err
		}
	}

	return nil
}

func (p *GitHubProvider) checkUserRestriction(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if len(p.Users) == 0 {
		return false, nil
	}

	verifiedUser, err := p.hasUser(ctx, s.AccessToken)

	if err != nil {
		return verifiedUser, err
	}

	// org and repository options are not configured
	if !verifiedUser && p.Org == "" && p.Repo == "" {
		return false, errors.New("missing github user")
	}

	return verifiedUser, nil
}

func (p *GitHubProvider) getOrgAndTeam(ctx context.Context, s *sessions.SessionState) error {
	err := p.getOrgs(ctx, s)
	if err != nil {
		return err
	}

	return p.getTeams(ctx, s)
}

func (p *GitHubProvider) getOrgs(ctx context.Context, s *sessions.SessionState) error {
	// https://docs.github.com/en/rest/orgs/orgs#list-organizations-for-the-authenticated-user

	type Organization struct {
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

		var orgs []Organization
		err := requests.New(endpoint.String()).
			WithContext(ctx).
			WithHeaders(makeGitHubHeader(s.AccessToken)).
			Do().
			UnmarshalInto(&orgs)
		if err != nil {
			return err
		}

		if len(orgs) == 0 {
			break
		}

		for _, org := range orgs {
			logger.Printf("Member of Github Organization:%q", org.Login)
			s.Groups = append(s.Groups, org.Login)
		}
		pn++
	}

	return nil
}

func (p *GitHubProvider) getTeams(ctx context.Context, s *sessions.SessionState) error {
	// https://docs.github.com/en/rest/teams/teams?#list-user-teams

	type Team struct {
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

		// bodyclose cannot detect that the body is being closed later in requests.Into,
		// so have to skip the linting for the next line.
		// nolint:bodyclose
		result := requests.New(endpoint.String()).
			WithContext(ctx).
			WithHeaders(makeGitHubHeader(s.AccessToken)).
			Do()

		if result.Error() != nil {
			return result.Error()
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

			link := result.Headers().Get("Link")
			rep1 := regexp.MustCompile(`(?s).*\<https://api.github.com/user/teams\?page=(.)&per_page=[0-9]+\>; rel="last".*`)
			i, converr := strconv.Atoi(rep1.ReplaceAllString(link, "$1"))

			// If the last page cannot be taken from the link in the http header, the last variable remains zero
			if converr == nil {
				last = i
			}
		}

		var teams []Team
		if err := result.UnmarshalInto(&teams); err != nil {
			return err
		}
		if len(teams) == 0 {
			break
		}

		for _, team := range teams {
			logger.Printf("Member of Github Organization/Team:%q/%q", team.Org.Login, team.Slug)
			s.Groups = append(s.Groups, team.Org.Login+"/"+team.Slug)
		}

		if pn == last {
			break
		}
		if last == 0 {
			break
		}

		pn++
	}

	return nil
}
