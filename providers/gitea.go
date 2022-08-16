package providers

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strconv"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// GiteaProvider represents a Gitea based Identity Provider
type GiteaProvider struct {
	*ProviderData
	Org   string
	Team  string
	Repo  string
	Token string
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
	provider.setRepo(opts.Repo, opts.Token)
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
func (p *GiteaProvider) setRepo(repo, token string) {
	p.Repo = repo
	p.Token = token
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

// ValidateSession validates the AccessToken
func (p *GiteaProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
}

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
		return false, nil
	}

	return true, nil
}

func (p *GiteaProvider) hasOrgAndTeam(ctx context.Context, accessToken string) (bool, error) {
	// https://try.gitea.io/api/swagger#/user/userListTeams

	type teamsPage []struct {
		TeamName string `json:"name"`
		Org      struct {
			OrgName string `json:"username"`
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
			Scheme:   p.getApiBase().Scheme,
			Host:     p.getApiBase().Host,
			Path:     path.Join(p.getApiBase().Path, "/user/teams"),
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

		if last == 0 {
			// link header may not be obtained
			// When paging is not required and all data can be retrieved with a single call

			// Conditions for obtaining the link header.
			// 1. When paging is required (Example: When the data size is 100 and the page size is 99 or less)
			// 2. When it exceeds the paging frame (Example: When there is only 10 records but the second page is called with a page size of 100)

			// link header at not last page
			// <https://api.gitea.com/user/teams?page=1&per_page=100>; rel="prev", <https://api.gitea.com/user/teams?page=1&per_page=100>; rel="last", <https://api.gitea.com/user/teams?page=1&per_page=100>; rel="first"
			// link header at last page (doesn't exist last info)
			// <https://api.gitea.com/user/teams?page=3&per_page=10>; rel="prev", <https://api.gitea.com/user/teams?page=1&per_page=10>; rel="first"

			link := result.Headers().Get("Link")
			rep1 := regexp.MustCompile(`(?s).*\<https://api.gitea.com/user/teams\?page=(.)&per_page=[0-9]+\>; rel="last".*`)
			i, converr := strconv.Atoi(rep1.ReplaceAllString(link, "$1"))

			// If the last page cannot be taken from the link in the http header, the last variable remains zero
			if converr == nil {
				last = i
			}
		}

		var tp teamsPage
		if err := result.UnmarshalInto(&tp); err != nil {
			return false, err
		}
		if len(tp) == 0 {
			break
		}

		for _, team := range tp {
			if team.Org.OrgName == p.Org && team.TeamName == p.Team {
				return true, nil
			}
		}

		if pn == last {
			break
		}
		if last == 0 {
			break
		}

		pn++
	}

	return false, nil
}

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
	err := requests.New(endpoint.String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(accessToken)).
		Do().
		UnmarshalInto(&repo)
	if err != nil {
		return false, err
	}

	// Every user can implicitly pull from a public repo, so only grant access
	// if they have push access or the repo is private and they can pull
	return repo.Permissions.Push || (repo.Private && repo.Permissions.Pull), nil
}

func (p *GiteaProvider) isCollaborator(ctx context.Context, username, accessToken string) (bool, error) {
	// https://try.gitea.io/api/swagger#/repository/repoCheckCollaborator

	endpoint := &url.URL{
		Scheme: p.getApiBase().Scheme,
		Host:   p.getApiBase().Host,
		Path:   path.Join(p.getApiBase().Path, "/repos/", p.Repo, "/collaborators/", username),
	}
	result := requests.New(endpoint.String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(accessToken)).
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

func (p *GiteaProvider) isAllowed(ctx context.Context, s *sessions.SessionState) error {
	// If a user is verified by username options, skip the following restrictions
	if len(p.Users) > 0 && !p.isVerifiedUser(s.User) {
		return errors.New(fmt.Sprintf("User %s is not verified.", s.User))
	}

	var ok bool
	var err error
	if p.Org != "" {
		if p.Team != "" {
			ok, err = p.hasOrgAndTeam(ctx, s.AccessToken)
		} else {
			ok, err = p.hasOrg(ctx, s.AccessToken, s.User)
		}
	} else if p.Repo != "" {
		if p.Token != "" {
			ok, err = p.isCollaborator(ctx, s.User, p.Token)
		} else {
			ok, err = p.hasRepo(ctx, s.AccessToken)
		}
	}

	if err != nil || !ok {
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
