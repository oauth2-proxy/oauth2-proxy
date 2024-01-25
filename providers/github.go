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
	"golang.org/x/exp/maps"
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
	orgTeamSeparator   = ":"
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

func (p *GitHubProvider) makeGitHubAPIEndpoint(endpoint string, params *url.Values) *url.URL {
	basePath := p.ValidateURL.Path

	re := regexp.MustCompile(`^/api/v\d+`)
	match := re.FindString(p.ValidateURL.Path)
	if match != "" {
		basePath = match
	}

	if params == nil {
		params = &url.Values{}
	}

	return &url.URL{
		Scheme:   p.ValidateURL.Scheme,
		Host:     p.ValidateURL.Host,
		Path:     path.Join(basePath, endpoint),
		RawQuery: params.Encode(),
	}
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
	if err := p.getOrgAndTeam(ctx, s); err != nil {
		return err
	}

	if err := p.checkRestrictions(ctx, s); err != nil {
		return err
	}

	if err := p.getEmail(ctx, s); err != nil {
		return err
	}

	return p.getUser(ctx, s)
}

// ValidateSession validates the AccessToken
func (p *GitHubProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeGitHubHeader(s.AccessToken))
}

func (p *GitHubProvider) hasOrg(s *sessions.SessionState) error {
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
			logger.Printf("Found Github Organization:%q", org)
			return nil
		}
		presentOrgs = append(presentOrgs, org)
	}

	logger.Printf("Missing Organization:%q in %v", p.Org, presentOrgs)
	return errors.New("user is missing required organization")
}

func (p *GitHubProvider) hasOrgAndTeam(s *sessions.SessionState) error {
	type orgTeam struct {
		Org  string `json:"org"`
		Team string `json:"team"`
	}

	var presentOrgTeams []orgTeam

	for _, group := range s.Groups {
		if strings.Contains(group, orgTeamSeparator) {
			ot := strings.Split(group, orgTeamSeparator)
			presentOrgTeams = append(presentOrgTeams, orgTeam{ot[0], ot[1]})
		}
	}

	var hasOrg bool

	presentOrgs := make(map[string]bool)
	var presentTeams []string

	for _, ot := range presentOrgTeams {
		presentOrgs[ot.Org] = true

		if strings.EqualFold(p.Org, ot.Org) {
			hasOrg = true
			teams := strings.Split(p.Team, ",")
			for _, team := range teams {
				if strings.EqualFold(strings.TrimSpace(team), ot.Team) {
					logger.Printf("Found Github Organization/Team:%q/%q", ot.Org, ot.Team)
					return nil
				}
			}
			presentTeams = append(presentTeams, ot.Team)
		}
	}

	if hasOrg {
		logger.Printf("Missing Team:%q from Org:%q in teams: %v", p.Team, p.Org, presentTeams)
		return errors.New("user is missing required team")
	}

	logger.Printf("Missing Organization:%q in %#v", p.Org, maps.Keys(presentOrgs))
	return errors.New("user is missing required organization")
}

func (p *GitHubProvider) hasRepoAccess(ctx context.Context, accessToken string) error {
	// https://developer.github.com/v3/repos/#get-a-repository

	type permissions struct {
		Pull bool `json:"pull"`
		Push bool `json:"push"`
	}

	type repository struct {
		Permissions permissions `json:"permissions"`
		Private     bool        `json:"private"`
	}

	endpoint := p.makeGitHubAPIEndpoint("/repos/"+p.Repo, nil)

	var repo repository
	err := requests.New(endpoint.String()).
		WithContext(ctx).
		WithHeaders(makeGitHubHeader(accessToken)).
		Do().
		UnmarshalInto(&repo)

	if err != nil {
		return err
	}

	// Every user can implicitly pull from a public repo, so only grant access
	// if they have push access or the repo is private and they can pull
	if repo.Permissions.Push || (repo.Private && repo.Permissions.Pull) {
		return nil
	}

	return errors.New("user doesn't have repository access")
}

func (p *GitHubProvider) hasUser(ctx context.Context, accessToken string) (bool, error) {
	// https://developer.github.com/v3/users/#get-the-authenticated-user

	var user struct {
		Login string `json:"login"`
		Email string `json:"email"`
	}

	endpoint := p.makeGitHubAPIEndpoint("/user", nil)

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

	endpoint := p.makeGitHubAPIEndpoint("/repos/"+p.Repo+"/collaborators/"+username, nil)
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

	endpoint := p.makeGitHubAPIEndpoint("/user/emails", nil)

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

	endpoint := p.makeGitHubAPIEndpoint("/user", nil)

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

func (p *GitHubProvider) isVerifiedUser(username string) bool {
	for _, u := range p.Users {
		if username == u {
			return true
		}
	}
	return false
}

func (p *GitHubProvider) checkRestrictions(ctx context.Context, s *sessions.SessionState) error {
	// If a user is verified by username options, skip the following restrictions
	if ok, err := p.checkUserRestriction(ctx, s); err != nil || ok {
		return err
	}

	if err := p.hasOrgAndTeamAccess(s); err != nil {
		return err
	}

	if p.Org == "" && p.Repo != "" && p.Token == "" {
		// If we have a token we'll do the collaborator check in GetUserName
		return p.hasRepoAccess(ctx, s.AccessToken)
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

func (p *GitHubProvider) hasOrgAndTeamAccess(s *sessions.SessionState) error {
	if p.Org != "" && p.Team != "" {
		return p.hasOrgAndTeam(s)
	}

	if p.Org != "" {
		return p.hasOrg(s)
	}

	return nil
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

		endpoint := p.makeGitHubAPIEndpoint("/user/orgs", &params)

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
	for {
		params := url.Values{
			"per_page": {"100"},
			"page":     {strconv.Itoa(pn)},
		}

		endpoint := p.makeGitHubAPIEndpoint("/user/teams", &params)

		var teams []Team
		err := requests.New(endpoint.String()).
			WithContext(ctx).
			WithHeaders(makeGitHubHeader(s.AccessToken)).
			Do().
			UnmarshalInto(&teams)
		if err != nil {
			return err
		}

		if len(teams) == 0 {
			break
		}

		for _, team := range teams {
			logger.Printf("Member of Github Organization/Team:%q/%q", team.Org.Login, team.Slug)
			s.Groups = append(s.Groups, team.Org.Login+orgTeamSeparator+team.Slug)
		}

		pn++
	}

	return nil
}
