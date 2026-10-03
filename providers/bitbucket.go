package providers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// BitbucketProvider represents a Bitbucket based Identity Provider.
//
// It supports two flavours of Bitbucket, selected by configuration:
//   - Bitbucket Cloud (bitbucket.org) - the default.
//   - Bitbucket Data Center / Server 7.20+ (self-hosted) - enabled by setting
//     --bitbucket-datacenter-url. This mirrors how the GitHub provider serves
//     both github.com and GitHub Enterprise.
//
// --bitbucket-workspace and --bitbucket-repository work in both modes:
//   - Cloud:       workspace slug, and "workspace/repo"
//   - Data Center: project key,    and "PROJECTKEY/repo-slug"
type BitbucketProvider struct {
	*ProviderData
	Workspace  string
	Repository string

	// DataCenterURL is the base URL (including any context path) of a
	// self-hosted Bitbucket Data Center instance. nil means Bitbucket Cloud.
	DataCenterURL *url.URL
}

var _ Provider = (*BitbucketProvider)(nil)

const (
	bitbucketProviderName = "Bitbucket"
	bitbucketDefaultScope = "email"

	// Data Center has no OIDC/userinfo endpoint and different scope names.
	bitbucketDataCenterProviderName = "Bitbucket Data Center"
	// PUBLIC_REPOS is the lowest-privilege Data Center scope and is enough to
	// read the authenticated user's own profile.
	bitbucketDataCenterDefaultScope = "PUBLIC_REPOS"
	// REPO_READ is required to see private projects/repositories when a
	// workspace (project) or repository restriction is configured.
	bitbucketDataCenterRepoReadScope = "REPO_READ"
	// Header Data Center uses to report the authenticated user's username.
	bitbucketDataCenterUsernameHeader = "X-AUSERNAME"
	bitbucketDataCenterOAuthPath      = "/rest/oauth2/latest"
	bitbucketDataCenterAPIPath        = "/rest/api/latest"
)

var (
	// Default Login URL for Bitbucket.
	// Pre-parsed URL of https://bitbucket.org/site/oauth2/authorize.
	bitbucketDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "bitbucket.org",
		Path:   "/site/oauth2/authorize",
	}

	// Default Redeem URL for Bitbucket.
	// Pre-parsed URL of https://bitbucket.org/site/oauth2/access_token.
	bitbucketDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "bitbucket.org",
		Path:   "/site/oauth2/access_token",
	}

	// Default Validation URL for Bitbucket.
	// This simply returns the email of the authenticated user.
	// Bitbucket does not have a Profile URL to use.
	// Pre-parsed URL of https://api.bitbucket.org/2.0/user/emails.
	bitbucketDefaultValidateURL = &url.URL{
		Scheme: "https",
		Host:   "api.bitbucket.org",
		Path:   "/2.0/user/emails",
	}
)

// NewBitbucketProvider initiates a new BitbucketProvider.
// When opts.DataCenterURL is set the provider targets Bitbucket Data Center
// and derives its login/redeem/validate URLs from it (each can still be
// overridden with --login-url/--redeem-url/--validate-url). The URL is
// checked by options validation before the provider is constructed.
func NewBitbucketProvider(p *ProviderData, opts options.BitbucketOptions) *BitbucketProvider {
	provider := &BitbucketProvider{ProviderData: p}

	if opts.DataCenterURL != "" {
		baseURL, err := url.Parse(strings.TrimSuffix(opts.DataCenterURL, "/"))
		if err != nil {
			// Unreachable after options validation; fail loudly rather than
			// silently falling back to bitbucket.org.
			logger.Fatalf("invalid bitbucket-datacenter-url %q: %v", opts.DataCenterURL, err)
		}
		provider.DataCenterURL = baseURL
		p.setProviderDefaults(providerDefaults{
			name:        bitbucketDataCenterProviderName,
			loginURL:    baseURL.JoinPath(bitbucketDataCenterOAuthPath, "authorize"),
			redeemURL:   baseURL.JoinPath(bitbucketDataCenterOAuthPath, "token"),
			profileURL:  nil,
			validateURL: baseURL.JoinPath(bitbucketDataCenterAPIPath, "application-properties"),
			scope:       bitbucketDataCenterDefaultScope,
		})
	} else {
		p.setProviderDefaults(providerDefaults{
			name:        bitbucketProviderName,
			loginURL:    bitbucketDefaultLoginURL,
			redeemURL:   bitbucketDefaultRedeemURL,
			profileURL:  nil,
			validateURL: bitbucketDefaultValidateURL,
			scope:       bitbucketDefaultScope,
		})
	}

	if opts.Team != "" {
		provider.setWorkspace(opts.Team)
	}
	if opts.Workspace != "" {
		provider.setWorkspace(opts.Workspace)
	}
	if opts.Repository != "" {
		provider.setRepository(opts.Repository)
	}
	return provider
}

// isDataCenter reports whether the provider targets Bitbucket Data Center.
func (p *BitbucketProvider) isDataCenter() bool {
	return p.DataCenterURL != nil
}

// addScope appends scope to p.Scope if it is not already present.
func (p *BitbucketProvider) addScope(scope string) {
	if !strings.Contains(p.Scope, scope) {
		p.Scope += " " + scope
	}
}

// setWorkspace defines the Bitbucket workspace (Cloud) or project key
// (Data Center) the user must be part of
func (p *BitbucketProvider) setWorkspace(workspace string) {
	p.Workspace = workspace
	if p.isDataCenter() {
		p.addScope(bitbucketDataCenterRepoReadScope)
		return
	}
	p.addScope("account")
}

// setRepository defines the repository the user must have access to
func (p *BitbucketProvider) setRepository(repository string) {
	p.Repository = repository
	if p.isDataCenter() {
		p.addScope(bitbucketDataCenterRepoReadScope)
		return
	}
	p.addScope("repository")
}

// Redeem exchanges the authorization code for tokens. Cloud uses the default
// implementation; Data Center keeps the refresh token and expiry so that
// --cookie-refresh can refresh sessions.
func (p *BitbucketProvider) Redeem(ctx context.Context, redirectURL, code, codeVerifier string) (*sessions.SessionState, error) {
	if !p.isDataCenter() {
		return p.ProviderData.Redeem(ctx, redirectURL, code, codeVerifier)
	}
	if code == "" {
		return nil, ErrMissingCode
	}

	params := url.Values{}
	params.Set("grant_type", "authorization_code")
	params.Set("redirect_uri", redirectURL)
	params.Set("code", code)
	if codeVerifier != "" {
		params.Set("code_verifier", codeVerifier)
	}

	token, err := p.dataCenterTokenRequest(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("failed to redeem Bitbucket authorization code: %v", err)
	}
	s := &sessions.SessionState{}
	applyBitbucketDataCenterToken(s, token)
	return s, nil
}

// RefreshSession uses the refresh token to obtain a new access token
// (Data Center only; Cloud keeps the default behaviour).
func (p *BitbucketProvider) RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if !p.isDataCenter() {
		return p.ProviderData.RefreshSession(ctx, s)
	}
	if s == nil || s.RefreshToken == "" {
		return false, nil
	}

	params := url.Values{}
	params.Set("grant_type", "refresh_token")
	params.Set("refresh_token", s.RefreshToken)

	token, err := p.dataCenterTokenRequest(ctx, params)
	if err != nil {
		return false, fmt.Errorf("unable to refresh Bitbucket token: %v", err)
	}
	applyBitbucketDataCenterToken(s, token)
	return true, nil
}

// ValidateSession validates the AccessToken using a Bearer token header
func (p *BitbucketProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	if p.isDataCenter() {
		if _, err := p.getDataCenterUsername(ctx, s.AccessToken); err != nil {
			logger.Errorf("bitbucket session validation failed: %v", err)
			return false
		}
		return true
	}
	return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
}

// EnrichSession populates the session for Data Center. Cloud is handled by
// GetEmailAddress, so this is a no-op there.
func (p *BitbucketProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	if !p.isDataCenter() {
		return nil
	}

	username, err := p.getDataCenterUsername(ctx, s.AccessToken)
	if err != nil {
		return fmt.Errorf("failed to resolve Bitbucket user: %v", err)
	}

	user, err := p.getDataCenterUser(ctx, s.AccessToken, username)
	if err != nil {
		return err
	}
	if !user.Active {
		return fmt.Errorf("bitbucket user %q is not active", user.Name)
	}

	s.User = user.Slug
	s.PreferredUsername = user.Name
	s.Email = user.EmailAddress
	if s.Email == "" {
		logger.Printf("bitbucket user %q has no email address", user.Name)
	}

	return p.checkDataCenterRestrictions(ctx, s)
}

// GetEmailAddress returns the email of the authenticated user (Cloud only;
// Data Center resolves the user in EnrichSession).
func (p *BitbucketProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	if p.isDataCenter() {
		return "", ErrNotImplemented
	}

	var emails struct {
		Values []struct {
			Email   string `json:"email"`
			Primary bool   `json:"is_primary"`
		}
	}
	var workspaces struct {
		Values []struct {
			Workspace struct {
				Slug string `json:"slug"`
			} `json:"workspace"`
		}
	}
	var repositories struct {
		Values []struct {
			FullName string `json:"full_name"`
		}
	}

	requestURL := p.ValidateURL.String()
	err := requests.New(requestURL).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(s.AccessToken)).
		Do().
		UnmarshalInto(&emails)
	if err != nil {
		logger.Errorf("failed making request: %v", err)
		return "", err
	}

	if p.Workspace != "" {
		teamURL := &url.URL{}
		*teamURL = *p.ValidateURL
		// /teams api was deprecated in Oct 20, use workspaces instead
		// https://developer.atlassian.com/cloud/bitbucket/bitbucket-api-teams-deprecation/
		// https://developer.atlassian.com/cloud/bitbucket/rest/api-group-workspaces/#api-workspaces-get
		teamURL.Path = "2.0/user/workspaces"

		requestURL := teamURL.String()

		err := requests.New(requestURL).
			WithContext(ctx).
			WithHeaders(makeOIDCHeader(s.AccessToken)).
			Do().
			UnmarshalInto(&workspaces)
		logger.Printf("workspaces: %+v", workspaces)
		if err != nil {
			logger.Errorf("failed requesting teams membership: %v", err)
			return "", err
		}
		var found = false
		for _, workspace := range workspaces.Values {
			if p.Workspace == workspace.Workspace.Slug {
				found = true
				break
			}
		}
		if !found {
			logger.Error("team membership test failed, access denied")
			return "", nil
		}
	}

	if p.Repository != "" {
		repositoriesURL := &url.URL{}
		*repositoriesURL = *p.ValidateURL
		// split the repository name to get the workspace name, which is the first part of the repository name
		var repoWorkspace = strings.Split(p.Repository, "/")[0]
		repositoriesURL.Path = "/2.0/repositories/" + repoWorkspace

		requestURL := repositoriesURL.String() + "?role=contributor" +
			"&q=full_name=" + url.QueryEscape("\""+p.Repository+"\"")

		err := requests.New(requestURL).
			WithContext(ctx).
			WithHeaders(makeOIDCHeader(s.AccessToken)).
			Do().
			UnmarshalInto(&repositories)
		if err != nil {
			logger.Errorf("failed checking repository access: %v", err)
			return "", err
		}

		var found = false
		for _, repository := range repositories.Values {
			if p.Repository == repository.FullName {
				found = true
				break
			}
		}
		if !found {
			logger.Error("repository access test failed, access denied")
			return "", nil
		}
	}

	for _, email := range emails.Values {
		if email.Primary {
			return email.Email, nil
		}
	}

	return "", nil
}

// ****************************************************************************
// Bitbucket Data Center helpers
//
// Data Center is not OIDC compliant and has no userinfo endpoint, so the user
// is resolved in two steps:
//  1. Any authenticated REST call returns the caller's username in the
//     X-AUSERNAME response header (application-properties is cheap and always
//     available).
//  2. /rest/api/latest/users/{slug} returns the profile (slug, email, ...).
//
// https://confluence.atlassian.com/bitbucketserver/bitbucket-oauth-2-0-provider-api-1108483661.html
// ****************************************************************************

// bitbucketDataCenterUser is the subset of /rest/api/latest/users/{slug} we use.
type bitbucketDataCenterUser struct {
	Name         string `json:"name"`
	Slug         string `json:"slug"`
	EmailAddress string `json:"emailAddress"`
	DisplayName  string `json:"displayName"`
	Active       bool   `json:"active"`
}

// bitbucketDataCenterTokenResponse is the JSON body of /rest/oauth2/latest/token.
type bitbucketDataCenterTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// dataCenterAPIURL builds an absolute REST API URL under the Data Center base URL.
func (p *BitbucketProvider) dataCenterAPIURL(elem ...string) *url.URL {
	return p.DataCenterURL.JoinPath(append([]string{bitbucketDataCenterAPIPath}, elem...)...)
}

// dataCenterTokenRequest POSTs a grant to the token endpoint.
func (p *BitbucketProvider) dataCenterTokenRequest(ctx context.Context, params url.Values) (*bitbucketDataCenterTokenResponse, error) {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return nil, err
	}
	params.Set("client_id", p.ClientID)
	params.Set("client_secret", clientSecret)

	var token bitbucketDataCenterTokenResponse
	err = requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod(http.MethodPost).
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetHeader(acceptHeader, acceptApplicationJSON).
		Do().
		UnmarshalInto(&token)
	if err != nil {
		return nil, err
	}
	if token.AccessToken == "" {
		return nil, errors.New("no access token in Bitbucket token response")
	}
	return &token, nil
}

// applyBitbucketDataCenterToken copies token fields into the session,
// including expiry so --cookie-refresh triggers RefreshSession in time.
func applyBitbucketDataCenterToken(s *sessions.SessionState, token *bitbucketDataCenterTokenResponse) {
	s.AccessToken = token.AccessToken
	if token.RefreshToken != "" {
		s.RefreshToken = token.RefreshToken
	}
	s.CreatedAtNow()
	if token.ExpiresIn > 0 {
		s.ExpiresIn(time.Duration(token.ExpiresIn) * time.Second)
	}
}

// getDataCenterUsername returns the token owner's username from X-AUSERNAME.
// application-properties also answers anonymous requests (without the
// header), so an empty header means the token is not authenticated.
func (p *BitbucketProvider) getDataCenterUsername(ctx context.Context, accessToken string) (string, error) {
	result := requests.New(p.ValidateURL.String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(accessToken)).
		Do()
	if result.Error() != nil {
		return "", result.Error()
	}
	if result.StatusCode() != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d from %s: %s", result.StatusCode(), p.ValidateURL, result.Body())
	}
	username := result.Headers().Get(bitbucketDataCenterUsernameHeader)
	if username == "" {
		return "", fmt.Errorf("no %s header in response; token is not authenticated", bitbucketDataCenterUsernameHeader)
	}
	// Bitbucket URL-encodes non-ASCII usernames in this header.
	if decoded, err := url.QueryUnescape(username); err == nil {
		username = decoded
	}
	return username, nil
}

// getDataCenterUser resolves the profile for username. The slug usually equals
// the username but can differ for names with special characters, so fall back
// to a filtered search with an exact name match.
func (p *BitbucketProvider) getDataCenterUser(ctx context.Context, accessToken, username string) (*bitbucketDataCenterUser, error) {
	var user bitbucketDataCenterUser
	err := requests.New(p.dataCenterAPIURL("users", username).String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(accessToken)).
		Do().
		UnmarshalInto(&user)
	if err == nil && user.Name != "" {
		return &user, nil
	}

	var page struct {
		Values []bitbucketDataCenterUser `json:"values"`
	}
	searchURL := p.dataCenterAPIURL("users")
	searchURL.RawQuery = url.Values{"filter": {username}, "limit": {"100"}}.Encode()
	if err := requests.New(searchURL.String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(accessToken)).
		Do().
		UnmarshalInto(&page); err != nil {
		return nil, fmt.Errorf("failed looking up user %q: %v", username, err)
	}
	for i := range page.Values {
		if page.Values[i].Name == username {
			return &page.Values[i], nil
		}
	}
	return nil, fmt.Errorf("user %q not found", username)
}

// dataCenterCanRead returns true when the token owner gets a 200 for the API
// path. Bitbucket returns 401/403/404 for projects/repos the user cannot see.
func (p *BitbucketProvider) dataCenterCanRead(ctx context.Context, accessToken string, elem ...string) (bool, error) {
	result := requests.New(p.dataCenterAPIURL(elem...).String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(accessToken)).
		Do()
	if result.Error() != nil {
		return false, result.Error()
	}
	switch result.StatusCode() {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status %d checking %s: %s", result.StatusCode(), strings.Join(elem, "/"), result.Body())
	}
}

// checkDataCenterRestrictions enforces --bitbucket-workspace (project key) and
// --bitbucket-repository (PROJECTKEY/repo-slug). Like Cloud, every configured
// restriction must pass.
func (p *BitbucketProvider) checkDataCenterRestrictions(ctx context.Context, s *sessions.SessionState) error {
	if p.Workspace != "" {
		ok, err := p.dataCenterCanRead(ctx, s.AccessToken, "projects", p.Workspace)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("user %q has no access to project %q", s.User, p.Workspace)
		}
	}

	if p.Repository != "" {
		parts := strings.SplitN(p.Repository, "/", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("invalid bitbucket-repository %q: expected PROJECTKEY/repo-slug", p.Repository)
		}
		ok, err := p.dataCenterCanRead(ctx, s.AccessToken, "projects", parts[0], "repos", parts[1])
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("user %q has no access to repository %q", s.User, p.Repository)
		}
	}

	return nil
}
