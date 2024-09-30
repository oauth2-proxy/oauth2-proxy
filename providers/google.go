package providers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/impersonate"
	"google.golang.org/api/option"
)

// GoogleProvider represents an Google based Identity Provider
type GoogleProvider struct {
	*ProviderData

	RedeemRefreshURL *url.URL

	// groupValidator is a function that determines if the user in the passed
	// session is a member of any of the configured Google groups.
	//
	// This hits the Google API for each group, so it is called on Redeem &
	// Refresh. `Authorize` uses the results of this saved in `session.Groups`
	// Since it is called on every request.
	groupValidator func(*sessions.SessionState) bool
}

var _ Provider = (*GoogleProvider)(nil)

type claims struct {
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

const (
	googleProviderName = "Google"
	googleDefaultScope = "profile email"
)

var (
	// Default Login URL for Google.
	// Pre-parsed URL of https://accounts.google.com/o/oauth2/auth?access_type=offline.
	googleDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "accounts.google.com",
		Path:   "/o/oauth2/auth",
		// to get a refresh token. see https://developers.google.com/identity/protocols/OAuth2WebServer#offline
		RawQuery: "access_type=offline",
	}

	// Default Redeem URL for Google.
	// Pre-parsed URL of https://www.googleapis.com/oauth2/v3/token.
	googleDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "www.googleapis.com",
		Path:   "/oauth2/v3/token",
	}

	// Default Validation URL for Google.
	// Pre-parsed URL of https://www.googleapis.com/oauth2/v1/tokeninfo.
	googleDefaultValidateURL = &url.URL{
		Scheme: "https",
		Host:   "www.googleapis.com",
		Path:   "/oauth2/v1/tokeninfo",
	}
)

// NewGoogleProvider initiates a new GoogleProvider
func NewGoogleProvider(p *ProviderData, opts options.GoogleOptions) (*GoogleProvider, error) {
	p.setProviderDefaults(providerDefaults{
		name:        googleProviderName,
		loginURL:    googleDefaultLoginURL,
		redeemURL:   googleDefaultRedeemURL,
		profileURL:  nil,
		validateURL: googleDefaultValidateURL,
		scope:       googleDefaultScope,
	})
	provider := &GoogleProvider{
		ProviderData: p,
		// Set a default groupValidator to just always return valid (true), it will
		// be overwritten if we configured a Google group restriction.
		groupValidator: func(*sessions.SessionState) bool {
			return true
		},
	}

	if opts.ServiceAccountJSON != "" || opts.UseApplicationDefaultCredentials {
		// Backwards compatibility with `--google-group` option
		if len(opts.Groups) > 0 {
			provider.setAllowedGroups(opts.Groups)
		}

		provider.setGroupRestriction(opts)
	}

	return provider, nil
}

func claimsFromIDToken(idToken string) (*claims, error) {

	// id_token is a base64 encode ID token payload
	// https://developers.google.com/accounts/docs/OAuth2Login#obtainuserinfo
	jwt := strings.Split(idToken, ".")
	jwtData := strings.TrimSuffix(jwt[1], "=")
	b, err := base64.RawURLEncoding.DecodeString(jwtData)
	if err != nil {
		return nil, err
	}

	c := &claims{}
	err = json.Unmarshal(b, c)
	if err != nil {
		return nil, err
	}
	if c.Email == "" {
		return nil, errors.New("missing email")
	}
	if !c.EmailVerified {
		return nil, fmt.Errorf("email %s not listed as verified", c.Email)
	}
	return c, nil
}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *GoogleProvider) Redeem(ctx context.Context, redirectURL, code, codeVerifier string) (*sessions.SessionState, error) {
	if code == "" {
		return nil, ErrMissingCode
	}
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return nil, err
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if codeVerifier != "" {
		params.Add("code_verifier", codeVerifier)
	}

	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		IDToken      string `json:"id_token"`
	}

	err = requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do().
		UnmarshalInto(&jsonResponse)
	if err != nil {
		return nil, err
	}

	c, err := claimsFromIDToken(jsonResponse.IDToken)
	if err != nil {
		return nil, err
	}

	ss := &sessions.SessionState{
		AccessToken:  jsonResponse.AccessToken,
		IDToken:      jsonResponse.IDToken,
		RefreshToken: jsonResponse.RefreshToken,
		Email:        c.Email,
		User:         c.Subject,
	}
	ss.CreatedAtNow()
	ss.ExpiresIn(time.Duration(jsonResponse.ExpiresIn) * time.Second)

	return ss, nil
}

// EnrichSession checks the listed Google Groups configured and adds any
// that the user is a member of to session.Groups.
func (p *GoogleProvider) EnrichSession(_ context.Context, s *sessions.SessionState) error {
	// TODO (@NickMeves) - Move to pure EnrichSession logic and stop
	// reusing legacy `groupValidator`.
	//
	// This is called here to get the validator to do the `session.Groups`
	// populating logic.
	p.groupValidator(s)

	return nil
}

// SetGroupRestriction configures the GoogleProvider to restrict access to the
// specified group(s). AdminEmail has to be an administrative email on the domain that is
// checked. CredentialsFile is the path to a json file containing a Google service
// account credentials.
//
// TODO (@NickMeves) - Unit Test this OR refactor away from groupValidator func
func (p *GoogleProvider) setGroupRestriction(opts options.GoogleOptions) {
	adminService := getAdminService(opts)
	p.groupValidator = func(s *sessions.SessionState) bool {
		// Reset our saved Groups in case membership changed
		// This is used by `Authorize` on every request
		s.Groups = make([]string, 0, len(opts.Groups))
		for _, group := range opts.Groups {
			if userInGroup(adminService, group, s.Email) {
				s.Groups = append(s.Groups, group)
			}
		}
		return len(s.Groups) > 0
	}
}

func getAdminService(opts options.GoogleOptions) *admin.Service {
	ctx := context.Background()
	var client *http.Client
	if opts.UseApplicationDefaultCredentials {
		ts, err := impersonate.CredentialsTokenSource(ctx, impersonate.CredentialsConfig{
			TargetPrincipal: getTargetPrincipal(ctx, opts),
			Scopes:          []string{admin.AdminDirectoryGroupReadonlyScope, admin.AdminDirectoryUserReadonlyScope},
			Subject:         opts.AdminEmail,
		})
		if err != nil {
			logger.Fatal("failed to fetch application default credentials: ", err)
		}
		client = oauth2.NewClient(ctx, ts)
	} else {
		credentialsReader, err := os.Open(opts.ServiceAccountJSON)
		if err != nil {
			logger.Fatal("couldn't open Google credentials file: ", err)
			return nil
		}

		data, err := io.ReadAll(credentialsReader)
		if err != nil {
			logger.Fatal("can't read Google credentials file:", err)
		}

		conf, err := google.JWTConfigFromJSON(data, admin.AdminDirectoryUserReadonlyScope, admin.AdminDirectoryGroupReadonlyScope)
		if err != nil {
			logger.Fatal("can't load Google credentials file:", err)
		}
		conf.Subject = opts.AdminEmail
		client = conf.Client(ctx)
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
	if s == nil || s.RefreshToken == "" {
		return false, nil
	}

	err := p.redeemRefreshToken(ctx, s)
	if err != nil {
		return false, err
	}

	// TODO (@NickMeves) - Align Group authorization needs with other providers'
	// behavior in the `RefreshSession` case.
	//
	// re-check that the user is in the proper google group(s)
	if !p.groupValidator(s) {
		return false, fmt.Errorf("%s is no longer in the group(s)", s.Email)
	}

	return true, nil
}

func (p *GoogleProvider) redeemRefreshToken(ctx context.Context, s *sessions.SessionState) error {
	// https://developers.google.com/identity/protocols/OAuth2WebServer#refresh
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return err
	}

	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("refresh_token", s.RefreshToken)
	params.Add("grant_type", "refresh_token")

	var data struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		IDToken     string `json:"id_token"`
	}

	err = requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do().
		UnmarshalInto(&data)
	if err != nil {
		return err
	}

	s.AccessToken = data.AccessToken
	s.IDToken = data.IDToken

	s.CreatedAtNow()
	s.ExpiresIn(time.Duration(data.ExpiresIn) * time.Second)

	return nil
}
