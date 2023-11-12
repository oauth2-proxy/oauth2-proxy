package providers

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

const (
	gitlabProviderName  = "GitLab"
	gitlabDefaultScope  = "openid email"
	gitlabProjectPrefix = "project:"
)

// GitLabProvider represents a GitLab based Identity Provider
type GitLabProvider struct {
	*OIDCProvider

	allowedProjects []*gitlabProject
	// Expose this for unit testing
	oidcRefreshFunc func(context.Context, *sessions.SessionState) (bool, error)
}

var _ Provider = (*GitLabProvider)(nil)

// NewGitLabProvider initiates a new GitLabProvider
func NewGitLabProvider(p *ProviderData, opts options.GitLabOptions) (*GitLabProvider, error) {
	p.setProviderDefaults(providerDefaults{
		name: gitlabProviderName,
	})

	if p.Scope == "" {
		p.Scope = gitlabDefaultScope
	}

	oidcProvider := NewOIDCProvider(p, options.OIDCOptions{InsecureSkipNonce: false})

	provider := &GitLabProvider{
		OIDCProvider:    oidcProvider,
		oidcRefreshFunc: oidcProvider.RefreshSession,
	}
	provider.setAllowedGroups(opts.Group)

	if err := provider.setAllowedProjects(opts.Projects); err != nil {
		return nil, fmt.Errorf("could not configure allowed projects: %v", err)
	}

	return provider, nil
}

// setAllowedProjects adds Gitlab projects to the AllowedGroups list
// and tracks them to do a project API lookup during `EnrichSession`.
func (p *GitLabProvider) setAllowedProjects(projects []string) error {
	for _, project := range projects {
		gp, err := newGitlabProject(project)
		if err != nil {
			return err
		}
		p.allowedProjects = append(p.allowedProjects, gp)
		p.AllowedGroups[formatProject(gp)] = struct{}{}
	}
	if len(p.allowedProjects) > 0 {
		p.setProjectScope()
	}
	return nil
}

// gitlabProject represents a Gitlab project constraint entity
type gitlabProject struct {
	Name        string
	AccessLevel int
}

// newGitlabProject Creates a new GitlabProject struct from project string
// formatted as `namespace/project=accesslevel`
// if no accesslevel provided, use the default one
func newGitlabProject(project string) (*gitlabProject, error) {
	const defaultAccessLevel = 20
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
				return &gitlabProject{
					Name:        parts[0],
					AccessLevel: lvl,
				}, nil
			}
		}
		return nil, fmt.Errorf("invalid gitlab project access level specified (%s)", parts[0])
	}

	return &gitlabProject{
		Name:        project,
		AccessLevel: defaultAccessLevel,
	}, nil
}

// setProjectScope ensures read_api is added to scope when filtering on projects
func (p *GitLabProvider) setProjectScope() {
	for _, val := range strings.Split(p.Scope, " ") {
		if val == "read_api" {
			return
		}
	}
	p.Scope += " read_api"
}

// EnrichSession enriches the session with the response from the userinfo API
// endpoint & projects API endpoint for allowed projects.
func (p *GitLabProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	// Retrieve user info
	userinfo, err := p.getUserinfo(ctx, s)
	if err != nil {
		return fmt.Errorf("failed to retrieve user info: %v", err)
	}

	// Check if email is verified
	if !p.AllowUnverifiedEmail && !userinfo.EmailVerified {
		return fmt.Errorf("user email is not verified")
	}

	if userinfo.Nickname != "" {
		s.User = userinfo.Nickname
	}
	if userinfo.Email != "" {
		s.Email = userinfo.Email
	}
	if len(userinfo.Groups) > 0 {
		s.Groups = userinfo.Groups
	}

	// Add projects as `project:blah` to s.Groups
	p.addProjectsToSession(ctx, s)

	return nil
}

type gitlabUserinfo struct {
	Nickname      string   `json:"nickname"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Groups        []string `json:"groups"`
}

func (p *GitLabProvider) getUserinfo(ctx context.Context, s *sessions.SessionState) (*gitlabUserinfo, error) {
	// Retrieve user info JSON
	// https://docs.gitlab.com/ee/integration/openid_connect_provider.html#shared-information

	// Build user info url from login url of GitLab instance
	userinfoURL := *p.LoginURL
	userinfoURL.Path = "/oauth/userinfo"

	var userinfo gitlabUserinfo
	err := requests.New(userinfoURL.String()).
		WithContext(ctx).
		SetHeader("Authorization", "Bearer "+s.AccessToken).
		Do().
		UnmarshalInto(&userinfo)
	if err != nil {
		return nil, fmt.Errorf("error getting user info: %v", err)
	}

	return &userinfo, nil
}

// addProjectsToSession adds projects matching user access requirements into
// the session state groups list.
// This method prefixes projects names with `project:` to specify group kind.
func (p *GitLabProvider) addProjectsToSession(ctx context.Context, s *sessions.SessionState) {
	// Iterate over projects, check if oauth2-proxy can get project information on behalf of the user
	for _, project := range p.allowedProjects {
		projectInfo, err := p.getProjectInfo(ctx, s, project.Name)
		if err != nil {
			logger.Errorf("Warning: project info request failed: %v", err)
			continue
		}

		if projectInfo.Archived {
			logger.Errorf("Warning: project %s is archived", project.Name)
			continue
		}

		perms := projectInfo.Permissions.ProjectAccess
		if perms == nil {
			// use group project access as fallback
			perms = projectInfo.Permissions.GroupAccess
			// group project access is not set for this user then we give up
			if perms == nil {
				logger.Errorf("Warning: user %q has no project level access to %s",
					s.Email, project.Name)
				continue
			}
		}

		if perms.AccessLevel < project.AccessLevel {
			logger.Errorf(
				"Warning: user %q does not have the minimum required access level for project %q",
				s.Email,
				project.Name,
			)
			continue
		}

		s.Groups = append(s.Groups, formatProject(project))
	}
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

func formatProject(project *gitlabProject) string {
	return gitlabProjectPrefix + project.Name
}

// RefreshSession refreshes the session with the OIDCProvider implementation
// but preserves the custom GitLab projects added in the `EnrichSession` stage.
func (p *GitLabProvider) RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error) {
	nickname := s.User
	projects := getSessionProjects(s)
	// This will overwrite s.Groups with the new IDToken's `groups` claims
	// and s.User with the `sub` claim.
	refreshed, err := p.oidcRefreshFunc(ctx, s)
	if refreshed && err == nil {
		s.User = nickname
		s.Groups = append(s.Groups, projects...)
		s.Groups = deduplicateGroups(s.Groups)
	}
	return refreshed, err
}

func getSessionProjects(s *sessions.SessionState) []string {
	var projects []string
	for _, group := range s.Groups {
		if strings.HasPrefix(group, gitlabProjectPrefix) {
			projects = append(projects, group)
		}
	}
	return projects
}

func deduplicateGroups(groups []string) []string {
	groupSet := make(map[string]struct{})
	for _, group := range groups {
		groupSet[group] = struct{}{}
	}

	uniqueGroups := make([]string, 0, len(groupSet))
	for group := range groupSet {
		uniqueGroups = append(uniqueGroups, group)
	}
	return uniqueGroups
}
