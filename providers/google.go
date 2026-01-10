package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"cloud.google.com/go/compute/metadata"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util/ptr"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

// GoogleProvider represents a Google based Identity Provider with OIDC-compliant ID token verification.
// This provider uses proper cryptographic verification of ID tokens per the OIDC spec,
// including signature verification via Google's JWKS, issuer validation, audience validation,
// and expiration checks.
type GoogleProvider struct {
	*OIDCProvider

	// adminService is used to fetch user's groups from Google Admin Directory API if configured.
	adminService *admin.Service

	// useOrganizationID indicates whether to use the organization ID from Admin API as preferred username.
	// If false, the 'name' claim from ID token is used instead.
	useOrganizationID bool

	// groupValidator is a function that determines if the user in the passed
	// session is a member of any of the configured Google groups.
	//
	// This hits the Google API for each group, so it is called on Redeem &
	// Refresh. `Authorize` uses the results of this saved in `session.Groups`
	// Since it is called on every request.
	groupValidator func(*sessions.SessionState) bool
}

var _ Provider = (*GoogleProvider)(nil)

const (
	googleProviderName     = "Google"
	googleDefaultIssuerURL = "https://accounts.google.com"
)

// setGoogleDefaults sets Google-specific defaults on the provider config.
// This is called before provider data is created to ensure proper OIDC discovery.
func setGoogleDefaults(providerConfig *options.Provider) {
	if providerConfig.OIDCConfig.IssuerURL == "" {
		providerConfig.OIDCConfig.IssuerURL = googleDefaultIssuerURL
	}
	if providerConfig.Scope != "" && !strings.Contains(providerConfig.Scope, "openid") {
		// Ensure openid scope is present for OIDC ID token verification
		providerConfig.Scope = "openid " + providerConfig.Scope
	}
}

// NewGoogleProvider initiates a new GoogleProvider with OIDC-compliant ID token verification
func NewGoogleProvider(p *ProviderData, opts options.GoogleOptions, oidcOpts options.OIDCOptions) *GoogleProvider {
	// Set Google-specific defaults
	if p.ProviderName == "" {
		p.ProviderName = googleProviderName
	}

	// Create the underlying OIDC provider (which sets default scope to "openid email profile")
	oidcProvider := NewOIDCProvider(p, oidcOpts)

	provider := &GoogleProvider{
		OIDCProvider: oidcProvider,
		// Set a default groupValidator to just always return valid (true), it will
		// be overwritten if we configured a Google group restriction.
		groupValidator: func(*sessions.SessionState) bool {
			return true
		},
		useOrganizationID: ptr.Deref(opts.UseOrganizationID, options.DefaultGoogleUseOrganizationID),
	}

	// Set up Google Admin API if configured
	if opts.ServiceAccountJSON != "" || ptr.Deref(opts.UseApplicationDefaultCredentials, options.DefaultUseApplicationDefaultCredentials) || provider.useOrganizationID {
		if provider.useOrganizationID {
			// add user scopes to admin api
			userScope := getAdminAPIUserScope(opts.AdminAPIUserScope)
			for index, scope := range possibleScopesList {
				possibleScopesList[index] = scope + " " + userScope
			}
		}

		provider.adminService = getAdminService(opts)

		// Configure group validation if service account is set up
		if opts.ServiceAccountJSON != "" || ptr.Deref(opts.UseApplicationDefaultCredentials, options.DefaultUseApplicationDefaultCredentials) {
			provider.configureGroups(opts, provider.adminService)
		}
	}

	return provider
}

// by default can be readonly user scope
func getAdminAPIUserScope(scope string) string {
	switch scope {
	case "cloud":
		return admin.CloudPlatformScope
	case "user":
		return admin.AdminDirectoryUserScope
	}
	return admin.AdminDirectoryUserReadonlyScope
}

func (p *GoogleProvider) configureGroups(opts options.GoogleOptions, adminService *admin.Service) {
	// Backwards compatibility with `--google-group` option
	if len(opts.Groups) > 0 {
		p.setAllowedGroups(opts.Groups)
		p.groupValidator = p.setGroupRestriction(opts.Groups, adminService)
		return
	}

	p.groupValidator = p.populateAllGroups(adminService)
}

// EnrichSession checks the listed Google Groups configured and adds any
// that the user is a member of to session.Groups.
// if preferred username is configured to be organization ID, it sets that as well.
func (p *GoogleProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	// First, call the parent OIDC EnrichSession
	if err := p.OIDCProvider.EnrichSession(ctx, s); err != nil {
		return err
	}

	// TODO (@NickMeves) - Move to pure EnrichSession logic and stop
	// reusing legacy `groupValidator`.
	//
	// This is called here to get the validator to do the `session.Groups`
	// populating logic.
	p.groupValidator(s)

	// Set preferredUsername
	if err := p.setPreferredUsername(s); err != nil {
		logger.Errorf("failed to set preferred username: %v", err)
	}

	return nil
}

// SetGroupRestriction configures the GoogleProvider to restrict access to the
// specified group(s).
func (p *GoogleProvider) setGroupRestriction(groups []string, adminService *admin.Service) func(*sessions.SessionState) bool {
	return func(s *sessions.SessionState) bool {
		// Reset our saved Groups in case membership changed
		// This is used by `Authorize` on every request
		s.Groups = make([]string, 0, len(groups))
		for _, group := range groups {
			if userInGroup(adminService, group, s.Email) {
				s.Groups = append(s.Groups, group)
			}
		}
		return len(s.Groups) > 0
	}
}

// populateAllGroups configures the GoogleProvider to allow access with all
// groups and populate session with all groups of the user when no specific
// groups are configured.
func (p *GoogleProvider) populateAllGroups(adminService *admin.Service) func(s *sessions.SessionState) bool {
	return func(s *sessions.SessionState) bool {
		// Get all groups of the user
		groups, err := getUserGroups(adminService, s.Email)
		if err != nil {
			logger.Errorf("Failed to get user groups for %s: %v", s.Email, err)
			s.Groups = []string{}
			return true // Allow access even if we can't get groups
		}

		// Populate session with all user groups
		s.Groups = groups
		return true // Always allow access when no specific groups are configured
	}
}

// setPreferredUsername sets the preferred username on the session.
// If useOrganizationID is true, it fetches the organization ID from Admin API.
// Otherwise, it extracts the 'name' claim from the ID token.
func (p *GoogleProvider) setPreferredUsername(s *sessions.SessionState) error {
	if p.useOrganizationID && p.adminService != nil {
		userName, err := getUserInfo(p.adminService, s.Email)
		if err != nil {
			return err
		}
		s.PreferredUsername = userName
		return nil
	}

	extractor, err := p.getClaimExtractor(s.IDToken, s.AccessToken)
	if err != nil {
		return fmt.Errorf("could not get claim extractor: %v", err)
	}

	var name string
	if exists, err := extractor.GetClaimInto("name", &name); err != nil || !exists {
		return nil
	}

	s.PreferredUsername = name
	return nil
}

// CreateSessionFromToken converts Bearer IDTokens into sessions
func (p *GoogleProvider) CreateSessionFromToken(ctx context.Context, token string) (*sessions.SessionState, error) {
	ss, err := p.OIDCProvider.CreateSessionFromToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("could not create session from token: %v", err)
	}

	// Populate groups via groupValidator
	if !p.groupValidator(ss) {
		return nil, fmt.Errorf("%s is not in the required group(s)", ss.Email)
	}

	// Set preferredUsername
	if err := p.setPreferredUsername(ss); err != nil {
		logger.Errorf("failed to set preferred username from bearer token: %v", err)
	}

	return ss, nil
}

// GetLoginURL makes the LoginURL with optional nonce support
func (p *GoogleProvider) GetLoginURL(redirectURI, state, nonce string, extraParams url.Values) string {
	// Add Google-specific parameters for offline access (refresh tokens)
	if extraParams == nil {
		extraParams = url.Values{}
	}
	if extraParams.Get("access_type") == "" {
		extraParams.Set("access_type", "offline")
	}
	return p.OIDCProvider.GetLoginURL(redirectURI, state, nonce, extraParams)
}

// https://developers.google.com/admin-sdk/directory/reference/rest/v1/members/hasMember#authorization-scopes
var possibleScopesList = [...]string{
	admin.AdminDirectoryGroupMemberReadonlyScope,
	admin.AdminDirectoryGroupReadonlyScope,
	admin.AdminDirectoryGroupMemberScope,
	admin.AdminDirectoryGroupScope,
}

func getOauth2TokenSource(ctx context.Context, opts options.GoogleOptions, scope string) oauth2.TokenSource {
	if ptr.Deref(opts.UseApplicationDefaultCredentials, options.DefaultUseApplicationDefaultCredentials) {
		ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: getTargetPrincipal(ctx, opts),
			Scopes:          strings.Split(scope, " "),
			Subject:         opts.AdminEmail,
		})
		if err != nil {
			logger.Fatal("failed to fetch application default credentials: ", err)
		}
		return ts
	}

	credentialsReader, err := os.Open(opts.ServiceAccountJSON)
	if err != nil {
		logger.Fatal("couldn't open Google credentials file: ", err)
	}

	data, err := io.ReadAll(credentialsReader)
	if err != nil {
		logger.Fatal("can't read Google credentials file:", err)
	}

	conf, err := google.JWTConfigFromJSON(data, scope)
	if err != nil {
		logger.Fatal("can't load Google credentials file:", err)
	}

	conf.Subject = opts.AdminEmail
	return conf.TokenSource(ctx)
}

// getAdminService retrieves an oauth token for the admin api of Google
// AdminEmail has to be an administrative email on the domain that is
// checked. CredentialsFile is the path to a json file containing a Google service
// account credentials.
func getAdminService(opts options.GoogleOptions) *admin.Service {
	ctx := context.Background()
	var client *http.Client

	for _, scope := range possibleScopesList {

		ts := getOauth2TokenSource(ctx, opts, scope)
		_, err := ts.Token()

		if err == nil {
			client = oauth2.NewClient(ctx, ts)
			break
		}

		if retrieveErr, ok := err.(*oauth2.RetrieveError); ok {
			retrieveErrBody := map[string]interface{}{}

			if err := json.Unmarshal(retrieveErr.Body, &retrieveErrBody); err != nil {
				logger.Fatal("error unmarshalling retrieveErr body:", err)
			}

			if retrieveErrBody["error"] == "unauthorized_client" && retrieveErrBody["error_description"] == "Client is unauthorized to retrieve access tokens using this method, or client not authorized for any of the scopes requested." {
				continue
			}

			logger.Fatal("error retrieving token:", err)
		}
	}

	if client == nil {
		logger.Fatal("error: google credentials do not have enough permissions to access admin API scope")
	}

	adminService, err := admin.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		logger.Fatal(err)
	}
	return adminService
}

func getTargetPrincipal(ctx context.Context, opts options.GoogleOptions) (targetPrincipal string) {
	targetPrincipal = opts.TargetPrincipal

	if targetPrincipal != "" {
		return targetPrincipal
	}
	logger.Print("INFO: no target principal set, trying to automatically determine one instead.")
	credential, err := google.FindDefaultCredentials(ctx)
	if err != nil {
		logger.Fatal("failed to fetch application default credentials: ", err)
	}
	content := map[string]interface{}{}

	err = json.Unmarshal(credential.JSON, &content)
	switch {
	case err != nil && !metadata.OnGCE():
		logger.Fatal("unable to unmarshal Application Default Credentials JSON", err)
	case content["client_email"] != nil:
		targetPrincipal = fmt.Sprintf("%v", content["client_email"])
	case metadata.OnGCE():
		targetPrincipal, err = metadata.EmailWithContext(ctx, "")
		if err != nil {
			logger.Fatal("error while calling the GCE metadata server", err)
		}
	default:
		logger.Fatal("unable to determine Application Default Credentials TargetPrincipal, try overriding with --target-principal instead.")
	}
	return targetPrincipal
}

func getUserInfo(service *admin.Service, email string) (string, error) {
	req := service.Users.Get(email)
	user, err := req.Do()
	if err != nil {
		return "", fmt.Errorf("failed to get user details for %s: %v", email, err)
	}

	ext, _ := user.ExternalIds.([]interface{})
	for _, v := range ext {
		m, _ := v.(map[string]interface{})
		if m == nil {
			continue
		}
		if t, _ := m["type"].(string); t != "organization" {
			continue
		}
		if val, _ := m["value"].(string); val != "" {
			return val, nil
		}
	}

	return "", fmt.Errorf("failed to get organization id for %s", email)
}

// getUserGroups retrieves all groups that a user is a member of using the Google Admin Directory API
func getUserGroups(service *admin.Service, email string) ([]string, error) {
	var allGroups []string
	var pageToken string

	for {
		req := service.Groups.List().UserKey(email).MaxResults(200)
		if pageToken != "" {
			req = req.PageToken(pageToken)
		}

		groupsResp, err := req.Do()
		if err != nil {
			return nil, fmt.Errorf("failed to list groups for user %s: %v", email, err)
		}

		for _, group := range groupsResp.Groups {
			if group.Email != "" {
				allGroups = append(allGroups, group.Email)
			}
		}

		// Check if there are more pages
		if groupsResp.NextPageToken == "" {
			break
		}
		pageToken = groupsResp.NextPageToken
	}

	return allGroups, nil
}

func userInGroup(service *admin.Service, group string, email string) bool {
	// Use the HasMember API to checking for the user's presence in each group or nested subgroups
	req := service.Members.HasMember(group, email)
	r, err := req.Do()
	if err == nil {
		return r.IsMember
	}

	gerr, ok := err.(*googleapi.Error)
	switch {
	case ok && gerr.Code == 404:
		logger.Errorf("error checking membership in group %s: group does not exist", group)
	case ok && gerr.Code == 400:
		// It is possible for Members.HasMember to return false even if the email is a group member.
		// One case that can cause this is if the user email is from a different domain than the group,
		// e.g. "member@otherdomain.com" in the group "group@mydomain.com" will result in a 400 error
		// from the HasMember API. In that case, attempt to query the member object directly from the group.
		req := service.Members.Get(group, email)
		r, err := req.Do()
		if err != nil {
			logger.Errorf("error using get API to check member %s of google group %s: user not in the group", email, group)
			return false
		}

		// If the non-domain user is found within the group, still verify that they are "ACTIVE".
		// Do not count the user as belonging to a group if they have another status ("ARCHIVED", "SUSPENDED", or "UNKNOWN").
		if r.Status == "ACTIVE" {
			return true
		}
	default:
		logger.Errorf("error checking group membership: %v", err)
	}
	return false
}

// RefreshSession uses the RefreshToken to fetch new Access and ID Tokens
func (p *GoogleProvider) RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error) {
	refreshed, err := p.OIDCProvider.RefreshSession(ctx, s)
	if err != nil || !refreshed {
		return refreshed, err
	}

	// TODO (@NickMeves) - Align Group authorization needs with other providers'
	// behavior in the `RefreshSession` case.
	//
	// re-check that the user is in the proper google group(s)
	if !p.groupValidator(s) {
		return false, fmt.Errorf("%s is no longer in the group(s)", s.Email)
	}

	// Update PreferredUsername
	if err := p.setPreferredUsername(s); err != nil {
		logger.Errorf("failed to set preferred username on refresh: %v", err)
	}

	return true, nil
}
