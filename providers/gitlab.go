package providers

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
	"golang.org/x/oauth2"
)

// GitLabProvider represents a GitLab based Identity Provider
type GitLabProvider struct {
	*ProviderData

	Groups   []string
	Projects []*GitlabProject
}

// GitlabProject represents a Gitlab project constraint entity
type GitlabProject struct {
	Name        string
	AccessLevel int
}

// newGitlabProject Creates a new GitlabProject struct from project string formatted as namespace/project=accesslevel
// if no accesslevel provided, use the default one
func newGitlabproject(project string) (*GitlabProject, error) {
	// default access level is 20
	defaultAccessLevel := 20
	// see https://docs.gitlab.com/ee/api/members.html#valid-access-levels
	validAccessLevel := [4]int{10, 20, 30, 40}

	parts := strings.SplitN(project, "=", 2)

	if len(parts) == 2 {
		lvl, err := strconv.Atoi(parts[1])
		if err != nil {
			return nil, err
		}

		for _, valid := range validAccessLevel {
			if lvl == valid {
				return &GitlabProject{
						Name:        parts[0],
						AccessLevel: lvl},
					err
			}
		}

		return nil, fmt.Errorf("invalid gitlab project access level specified (%s)", parts[0])

	}

	return &GitlabProject{
			Name:        project,
			AccessLevel: defaultAccessLevel},
		nil

}

var _ Provider = (*GitLabProvider)(nil)

const (
	gitlabProviderName = "GitLab"
	gitlabDefaultScope = "openid email"
)

// NewGitLabProvider initiates a new GitLabProvider
func NewGitLabProvider(p *ProviderData) *GitLabProvider {
	p.ProviderName = gitlabProviderName

	if p.Scope == "" {
		p.Scope = gitlabDefaultScope
	}

	return &GitLabProvider{ProviderData: p}
}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *GitLabProvider) Redeem(ctx context.Context, redirectURL, code string) (s *sessions.SessionState, err error) {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return
	}

	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
		RedirectURL: redirectURL,
	}
	token, err := c.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %v", err)
	}
	s, err = p.createSession(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("unable to update session: %v", err)
	}
	return
}

// SetProjectScope ensure read_api is added to scope when filtering on projects
func (p *GitLabProvider) SetProjectScope() {
	if len(p.Projects) > 0 {
		for _, val := range strings.Split(p.Scope, " ") {
			if val == "read_api" {
				return
			}

		}
		p.Scope += " read_api"
	}
}

// RefreshSessionIfNeeded checks if the session has expired and uses the
// RefreshToken to fetch a new ID token if required
func (p *GitLabProvider) RefreshSessionIfNeeded(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if s == nil || (s.ExpiresOn != nil && s.ExpiresOn.After(time.Now())) || s.RefreshToken == "" {
		return false, nil
	}

	origExpiration := s.ExpiresOn

	err := p.redeemRefreshToken(ctx, s)
	if err != nil {
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	logger.Printf("refreshed id token %s (expired on %s)\n", s, origExpiration)
	return true, nil
}

func (p *GitLabProvider) redeemRefreshToken(ctx context.Context, s *sessions.SessionState) (err error) {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return
	}

	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
	}
	t := &oauth2.Token{
		RefreshToken: s.RefreshToken,
		Expiry:       time.Now().Add(-time.Hour),
	}
	token, err := c.TokenSource(ctx, t).Token()
	if err != nil {
		return fmt.Errorf("failed to get token: %v", err)
	}
	newSession, err := p.createSession(ctx, token)
	if err != nil {
		return fmt.Errorf("unable to update session: %v", err)
	}
	s.AccessToken = newSession.AccessToken
	s.IDToken = newSession.IDToken
	s.RefreshToken = newSession.RefreshToken
	s.CreatedAt = newSession.CreatedAt
	s.ExpiresOn = newSession.ExpiresOn
	s.Email = newSession.Email
	return
}

type gitlabUserInfo struct {
	Username      string   `json:"nickname"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Groups        []string `json:"groups"`
}

func (p *GitLabProvider) getUserInfo(ctx context.Context, s *sessions.SessionState) (*gitlabUserInfo, error) {
	// Retrieve user info JSON
	// https://docs.gitlab.com/ee/integration/openid_connect_provider.html#shared-information

	// Build user info url from login url of GitLab instance
	userInfoURL := *p.LoginURL
	userInfoURL.Path = "/oauth/userinfo"

	var userInfo gitlabUserInfo
	err := requests.New(userInfoURL.String()).
		WithContext(ctx).
		SetHeader("Authorization", "Bearer "+s.AccessToken).
		Do().
		UnmarshalInto(&userInfo)
	if err != nil {
		return nil, fmt.Errorf("error getting user info: %v", err)
	}

	return &userInfo, nil
}

type gitlabPermissionAccess struct {
	AccessLevel int `json:"access_level"`
}

type gitlabProjectPermission struct {
	ProjectAccess *gitlabPermissionAccess `json:"project_access"`
	GroupAccess   *gitlabPermissionAccess `json:"group_access"`
}

type gitlabProjectInfo struct {
	Name              string                  `json:"name"`
	Archived          bool                    `json:"archived"`
	PathWithNamespace string                  `json:"path_with_namespace"`
	Permissions       gitlabProjectPermission `json:"permissions"`
}

func (p *GitLabProvider) getProjectInfo(ctx context.Context, s *sessions.SessionState, project string) (*gitlabProjectInfo, error) {
	var projectInfo gitlabProjectInfo

	endpointURL := &url.URL{
		Scheme: p.LoginURL.Scheme,
		Host:   p.LoginURL.Host,
		Path:   "/api/v4/projects/",
	}

	err := requests.New(fmt.Sprintf("%s%s", endpointURL.String(), url.QueryEscape(project))).
		WithContext(ctx).
		SetHeader("Authorization", "Bearer "+s.AccessToken).
		Do().
		UnmarshalInto(&projectInfo)

	if err != nil {
		return nil, fmt.Errorf("failed to get project info: %v", err)
	}

	return &projectInfo, nil
}

// AddProjects adds Gitlab projects from options to GitlabProvider struct
func (p *GitLabProvider) AddProjects(projects []string) error {
	for _, project := range projects {
		gp, err := newGitlabproject(project)
		if err != nil {
			return err
		}

		p.Projects = append(p.Projects, gp)
	}

	return nil
}

func (p *GitLabProvider) createSession(ctx context.Context, token *oauth2.Token) (*sessions.SessionState, error) {
	idToken, err := p.verifyIDToken(ctx, token)
	if err != nil {
		switch err {
		case ErrMissingIDToken:
			return nil, fmt.Errorf("token response did not contain an id_token")
		default:
			return nil, fmt.Errorf("could not verify id_token: %v", err)
		}
	}

	created := time.Now()
	return &sessions.SessionState{
		AccessToken:  token.AccessToken,
		IDToken:      getIDToken(token),
		RefreshToken: token.RefreshToken,
		CreatedAt:    &created,
		ExpiresOn:    &idToken.Expiry,
	}, nil
}

// ValidateSession checks that the session's IDToken is still valid
func (p *GitLabProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	_, err := p.Verifier.Verify(ctx, s.IDToken)
	return err == nil
}

// EnrichSession adds values and data from the Gitlab endpoint to current session
func (p *GitLabProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	// Retrieve user info
	userInfo, err := p.getUserInfo(ctx, s)
	if err != nil {
		return fmt.Errorf("failed to retrieve user info: %v", err)
	}

	// Check if email is verified
	if !p.AllowUnverifiedEmail && !userInfo.EmailVerified {
		return fmt.Errorf("user email is not verified")
	}

	s.User = userInfo.Username
	s.Email = userInfo.Email

	p.addGroupsToSession(ctx, s)

	p.addProjectsToSession(ctx, s)

	return nil

}

// addGroupsToSession projects into session.Groups
func (p *GitLabProvider) addGroupsToSession(ctx context.Context, s *sessions.SessionState) {
	// Iterate over projects, check if oauth2-proxy can get project information on behalf of the user
	for _, group := range p.Groups {
		s.Groups = append(s.Groups, fmt.Sprintf("group:%s", group))
	}
}

// addProjectsToSession adds projects matching user access requirements into the session state groups list
// This method prefix projects names with `project` to specify group kind
func (p *GitLabProvider) addProjectsToSession(ctx context.Context, s *sessions.SessionState) {
	// Iterate over projects, check if oauth2-proxy can get project information on behalf of the user
	for _, project := range p.Projects {
		projectInfo, err := p.getProjectInfo(ctx, s, project.Name)

		if err != nil {
			logger.Errorf("Warning: project info request failed: %v", err)
			continue
		}

		if !projectInfo.Archived {
			perms := projectInfo.Permissions.ProjectAccess
			if perms == nil {
				// use group project access as fallback
				perms = projectInfo.Permissions.GroupAccess
				// group project access is not set for this user then we give up
				if perms == nil {
					logger.Errorf("Warning: user %q has no project level access to %s", s.Email, project.Name)
					continue
				}
			}

			if perms != nil && perms.AccessLevel >= project.AccessLevel {
				s.Groups = append(s.Groups, fmt.Sprintf("project:%s", project.Name))
			} else {
				logger.Errorf("Warning: user %q does not have the minimum required access level for project %q", s.Email, project.Name)
			}
		} else {
			logger.Errorf("Warning: project %s is archived", project.Name)
		}

	}

}

// PrefixAllowedGroups returns a list of allowed groups, prefixed by their `kind` value
func (p *GitLabProvider) PrefixAllowedGroups() (groups []string) {

	for _, val := range p.Groups {
		groups = append(groups, fmt.Sprintf("group:%s", val))
	}

	for _, val := range p.Projects {
		groups = append(groups, fmt.Sprintf("project:%s", val.Name))
	}

	return groups
}
