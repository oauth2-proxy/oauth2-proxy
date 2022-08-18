package providers

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strconv"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// GiteaProvider represents a Gitea based Identity Provider
type GiteaProvider struct {
	*ProviderData
	Org   string
	Team  string
	Repo  string
	Users []string
}

var _ Provider = (*GiteaProvider)(nil)

const (
	giteaProviderName = "Gitea"
)

var (
	// Default Login URL for Gitea.
	// Pre-parsed URL of https://try.gitea.io/login/oauth/authorize.
	giteaDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "try.gitea.io",
		Path:   "/login/oauth/authorize",
	}

	// Default Redeem URL for Gitea.
	// Pre-parsed URL of https://try.gitea.io/login/oauth/access_token.
	giteaDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "try.gitea.io",
		Path:   "/login/oauth/access_token",
	}

	// Default Validation URL for Gitea.
	// ValidationURL is not the API Base URL, because the API Base URL returns 404.
	// https://github.com/oauth2-proxy/oauth2-proxy/issues/1636
	// Other API requests are based off of this (eg to fetch users/groups).
	// Pre-parsed URL of https://try.gitea.io/api/v1/user.
	giteaDefaultValidateURL = &url.URL{
		Scheme: "https",
		Host:   "try.gitea.io",
		Path:   "/api/v1/user",
	}
)

// NewGiteaProvider initiates a new GiteaProvider
func NewGiteaProvider(p *ProviderData, opts options.GiteaOptions) *GiteaProvider {
	p.setProviderDefaults(providerDefaults{
		name:        giteaProviderName,
		loginURL:    giteaDefaultLoginURL,
		redeemURL:   giteaDefaultRedeemURL,
		profileURL:  nil,
		validateURL: giteaDefaultValidateURL,
	})

	provider := &GiteaProvider{ProviderData: p}

	provider.setOrgTeam(opts.Org, opts.Team)
	provider.setRepo(opts.Repo)
	provider.setUsers(opts.Users)
	return provider
}

func (p *GiteaProvider) getApiBase() *url.URL {
	if p.ValidateURL == nil {
		return nil
	} else {
		apiBase := &url.URL{
			Scheme: p.ValidateURL.Scheme,
			Host:   p.ValidateURL.Host,
			Path:   path.Dir(p.ValidateURL.Path),
		}
		return apiBase
	}
}

// setOrgTeam configures the target org and team
func (p *GiteaProvider) setOrgTeam(org, team string) {
	p.Org = org
	p.Team = team
}

// setRepo configures the target repository and optional token to use
func (p *GiteaProvider) setRepo(repo string) {
	p.Repo = repo
}

// setUsers configures allowed usernames
func (p *GiteaProvider) setUsers(users []string) {
	p.Users = users
}

// EnrichSession updates the User & Email after the initial Redeem
func (p *GiteaProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	if err := p.getEmail(ctx, s); err != nil {
		return err
	}
	if err := p.getUser(ctx, s); err != nil {
		return err
	}
	if err := p.isAllowed(ctx, s); err != nil {
		return err
	}

	return nil
}

// Checks whether the user is in the organization
func (p *GiteaProvider) hasOrg(ctx context.Context, accessToken string, userName string) (bool, error) {
	// https://try.gitea.io/api/swagger#/organization/orgIsMember

	endpoint := &url.URL{
		Scheme: p.getApiBase().Scheme,
		Host:   p.getApiBase().Host,
		Path:   path.Join(p.getApiBase().Path, "/orgs/", p.Org, "/members/", userName),
	}

	result := requests.New(endpoint.String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(accessToken)).
		Do()

	if result.Error() != nil {
		return false, result.Error()
	}

	if result.StatusCode() != 204 {
		return false, errors.New(fmt.Sprintf("user is not in org %s", p.Org))
	}

	return true, nil
}

// Checks whether the user is in the team of the organization
func (p *GiteaProvider) hasOrgAndTeam(ctx context.Context, accessToken string, userName string) (bool, error) {
	// https://try.gitea.io/api/swagger#/user/userListTeams
	// blocked by https://github.com/go-gitea/gitea/issues/20829
	// http://try.gitea.io/api/swagger#/organization/orgListTeams
	// consider http://try.gitea.io/api/swagger#/settings/getGeneralAPISettings for getting max_response_items

	type team struct {
		Id   int    `json:"id"`
		Name string `json:"name"`
	}

	type teamPage []team

	var allowedTeam *team

	// Find the allowedTeam to get the id
	pn := 1
	count := 0
	for {
		params := url.Values{
			"per_page": {"100"},
			"page":     {strconv.Itoa(pn)},
		}

		endpoint := &url.URL{
			Scheme:   p.getApiBase().Scheme,
			Host:     p.getApiBase().Host,
			Path:     path.Join(p.getApiBase().Path, "/orgs/", p.Org, "/teams"),
			RawQuery: params.Encode(),
		}

		// bodyclose cannot detect that the body is being closed later in requests.Into,
		// so have to skip the linting for the next line.
		// nolint:bodyclose
		result := requests.New(endpoint.String()).
			WithContext(ctx).
			WithHeaders(makeOIDCHeader(accessToken)).
			Do()
		if result.Error() != nil {
			return false, result.Error()
		}
		if result.StatusCode() == 403 {
			return false, errors.New(fmt.Sprintf("user is not allowed to access org %s", p.Org))
		}
		totalCount, err := strconv.Atoi(result.Headers().Get("x-total-count"))
		if err != nil {
			return false, err
		}

		var teamsPage teamPage
		if err := result.UnmarshalInto(&teamsPage); err != nil {
			return false, err
		}
		if len(teamsPage) == 0 {
			break
		}

		for _, team := range teamsPage {
			count++
			if team.Name == p.Team {
				allowedTeam = &team
				break
			}
		}

		if allowedTeam != nil {
			break
		}

		if count == totalCount {
			break
		}

		pn++
	}

	if allowedTeam == nil {
		return false, errors.New(fmt.Sprintf("team %s does not exist in org %s", p.Team, p.Org))
	}

	// http://try.gitea.io/api/swagger#/organization/orgListTeamMember
	// Check if the user is a team member
	endpoint := &url.URL{
		Scheme: p.getApiBase().Scheme,
		Host:   p.getApiBase().Host,
		Path:   path.Join(p.getApiBase().Path, "/teams/", strconv.Itoa(allowedTeam.Id), "/members/", userName),
	}

	result := requests.New(endpoint.String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(accessToken)).
		Do()

	if result.Error() != nil {
		return false, result.Error()
	}

	if result.StatusCode() == 200 {
		return true, nil
	} else {
		return false, errors.New(fmt.Sprintf("user is not in the team %s of org %s", p.Team, p.Org))
	}
}

// Checks whether the user has access to the repository.
// For public repos the user needs push permission.
// For private repos the user needs pull or push permission.
func (p *GiteaProvider) hasRepo(ctx context.Context, accessToken string) (bool, error) {
	// https://try.gitea.io/api/swagger#/repository/repoGet

	type permissions struct {
		Pull bool `json:"pull"`
		Push bool `json:"push"`
	}

	type repository struct {
		Permissions permissions `json:"permissions"`
		Private     bool        `json:"private"`
	}

	endpoint := &url.URL{
		Scheme: p.getApiBase().Scheme,
		Host:   p.getApiBase().Host,
		Path:   path.Join(p.getApiBase().Path, "/repos/", p.Repo),
	}

	var repo repository
	result := requests.New(endpoint.String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(accessToken)).
		Do()
	if result.Error() != nil {
		return false, result.Error()
	}
	if result.StatusCode() == 404 {
		return false, errors.New(fmt.Sprintf("repo %s is not visible for this user or doesn't exist", p.Repo))
	}
	if err := result.UnmarshalInto(&repo); err != nil {
		return false, err
	}

	// Every user can implicitly pull from a public repo, so only grant access
	// if they have push access or the repo is private and they can pull
	if repo.Permissions.Push || (repo.Private && repo.Permissions.Pull) {
		return true, nil
	} else {
		return false, errors.New(fmt.Sprintf("user is not in repo %s", p.Repo))
	}
}

// getEmail updates the SessionState Email
func (p *GiteaProvider) getEmail(ctx context.Context, s *sessions.SessionState) error {

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}

	endpoint := &url.URL{
		Scheme: p.getApiBase().Scheme,
		Host:   p.getApiBase().Host,
		Path:   path.Join(p.getApiBase().Path, "/user/emails"),
	}
	err := requests.New(endpoint.String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(s.AccessToken)).
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
func (p *GiteaProvider) getUser(ctx context.Context, s *sessions.SessionState) error {
	var user struct {
		Login string `json:"login"`
	}

	endpoint := &url.URL{
		Scheme: p.getApiBase().Scheme,
		Host:   p.getApiBase().Host,
		Path:   path.Join(p.getApiBase().Path, "/user"),
	}

	err := requests.New(endpoint.String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(s.AccessToken)).
		Do().
		UnmarshalInto(&user)
	if err != nil {
		return err
	}

	s.User = user.Login
	return nil
}

// Checks whether the user is allowed to pass.
// Returns an error if the user is not allowed
func (p *GiteaProvider) isAllowed(ctx context.Context, s *sessions.SessionState) error {
	// If a user is verified by username options, skip the following restrictions
	if len(p.Users) > 0 && !p.isVerifiedUser(s.User) && p.Org == "" && p.Repo == "" {
		return errors.New(fmt.Sprintf("user is not in allowed users %s", p.Users))
	} else if len(p.Users) > 0 && p.isVerifiedUser(s.User) {
		return nil
	}

	ok := true
	var err error
	if p.Org != "" {
		if p.Team != "" {
			ok, err = p.hasOrgAndTeam(ctx, s.AccessToken, s.User)
		} else {
			ok, err = p.hasOrg(ctx, s.AccessToken, s.User)
		}
	} else if p.Repo != "" {
		ok, err = p.hasRepo(ctx, s.AccessToken)
	}

	if err != nil || !ok {
		// if s.Email == "" && err == nil { 403 gets returned }
		s.Email = ""
		return err
	} else {
		return nil
	}
}

// isVerifiedUser
func (p *GiteaProvider) isVerifiedUser(username string) bool {
	for _, u := range p.Users {
		if username == u {
			return true
		}
	}
	return false
}
