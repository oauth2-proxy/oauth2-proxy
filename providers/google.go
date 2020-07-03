package providers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/url"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/requests"
	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

// GoogleProvider represents an Google based Identity Provider
type GoogleProvider struct {
	*ProviderData
	RedeemRefreshURL *url.URL
	// GroupValidator is a function that determines if the passed email is in
	// the configured Google group.
	GroupValidator func(string) bool
}

var _ Provider = (*GoogleProvider)(nil)

type claims struct {
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

// NewGoogleProvider initiates a new GoogleProvider
func NewGoogleProvider(p *ProviderData) *GoogleProvider {
	p.ProviderName = "Google"
	if p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{Scheme: "https",
			Host: "accounts.google.com",
			Path: "/o/oauth2/auth",
			// to get a refresh token. see https://developers.google.com/identity/protocols/OAuth2WebServer#offline
			RawQuery: "access_type=offline",
		}
	}
	if p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{Scheme: "https",
			Host: "www.googleapis.com",
			Path: "/oauth2/v3/token"}
	}
	if p.ValidateURL.String() == "" {
		p.ValidateURL = &url.URL{Scheme: "https",
			Host: "www.googleapis.com",
			Path: "/oauth2/v1/tokeninfo"}
	}
	if p.Scope == "" {
		p.Scope = "profile email"
	}

	return &GoogleProvider{
		ProviderData: p,
		// Set a default GroupValidator to just always return valid (true), it will
		// be overwritten if we configured a Google group restriction.
		GroupValidator: func(email string) bool {
			return true
		},
	}
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
func (p *GoogleProvider) Redeem(ctx context.Context, redirectURL, code string) (s *sessions.SessionState, err error) {
	if code == "" {
		err = errors.New("missing code")
		return
	}
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")

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
		UnmarshalInto(&jsonResponse)
	if err != nil {
		return nil, err
	}

	c, err := claimsFromIDToken(jsonResponse.IDToken)
	if err != nil {
		return
	}

	created := time.Now()
	expires := time.Now().Add(time.Duration(jsonResponse.ExpiresIn) * time.Second).Truncate(time.Second)
	s = &sessions.SessionState{
		AccessToken:  jsonResponse.AccessToken,
		IDToken:      jsonResponse.IDToken,
		CreatedAt:    &created,
		ExpiresOn:    &expires,
		RefreshToken: jsonResponse.RefreshToken,
		Email:        c.Email,
		User:         c.Subject,
	}
	return
}

// SetGroupRestriction configures the GoogleProvider to restrict access to the
// specified group(s). AdminEmail has to be an administrative email on the domain that is
// checked. CredentialsFile is the path to a json file containing a Google service
// account credentials.
func (p *GoogleProvider) SetGroupRestriction(groups []string, adminEmail string, credentialsReader io.Reader) {
	adminService := getAdminService(adminEmail, credentialsReader)
	p.GroupValidator = func(email string) bool {
		return userInGroup(adminService, groups, email)
	}
}

func getAdminService(adminEmail string, credentialsReader io.Reader) *admin.Service {
	data, err := ioutil.ReadAll(credentialsReader)
	if err != nil {
		logger.Fatal("can't read Google credentials file:", err)
	}
	conf, err := google.JWTConfigFromJSON(data, admin.AdminDirectoryUserReadonlyScope, admin.AdminDirectoryGroupReadonlyScope)
	if err != nil {
		logger.Fatal("can't load Google credentials file:", err)
	}
	conf.Subject = adminEmail

	ctx := context.Background()
	client := conf.Client(ctx)
	adminService, err := admin.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		logger.Fatal(err)
	}
	return adminService
}

func userInGroup(service *admin.Service, groups []string, email string) bool {
	for _, group := range groups {
		// Use the HasMember API to checking for the user's presence in each group or nested subgroups
		req := service.Members.HasMember(group, email)
		r, err := req.Do()
		if err != nil {
			gerr, ok := err.(*googleapi.Error)
			switch {
			case ok && gerr.Code == 404:
				logger.Printf("error checking membership in group %s: group does not exist", group)
			case ok && gerr.Code == 400:
				// It is possible for Members.HasMember to return false even if the email is a group member.
				// One case that can cause this is if the user email is from a different domain than the group,
				// e.g. "member@otherdomain.com" in the group "group@mydomain.com" will result in a 400 error
				// from the HasMember API. In that case, attempt to query the member object directly from the group.
				req := service.Members.Get(group, email)
				r, err := req.Do()

				if err != nil {
					logger.Printf("error using get API to check member %s of google group %s: user not in the group", email, group)
					continue
				}

				// If the non-domain user is found within the group, still verify that they are "ACTIVE".
				// Do not count the user as belonging to a group if they have another status ("ARCHIVED", "SUSPENDED", or "UNKNOWN").
				if r.Status == "ACTIVE" {
					return true
				}
			default:
				logger.Printf("error checking group membership: %v", err)
			}
			continue
		}
		if r.IsMember {
			return true
		}
	}
	return false
}

// ValidateGroup validates that the provided email exists in the configured Google
// group(s).
func (p *GoogleProvider) ValidateGroup(email string) bool {
	return p.GroupValidator(email)
}

// RefreshSessionIfNeeded checks if the session has expired and uses the
// RefreshToken to fetch a new ID token if required
func (p *GoogleProvider) RefreshSessionIfNeeded(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if s == nil || (s.ExpiresOn != nil && s.ExpiresOn.After(time.Now())) || s.RefreshToken == "" {
		return false, nil
	}

	newToken, newIDToken, duration, err := p.redeemRefreshToken(ctx, s.RefreshToken)
	if err != nil {
		return false, err
	}

	// re-check that the user is in the proper google group(s)
	if !p.ValidateGroup(s.Email) {
		return false, fmt.Errorf("%s is no longer in the group(s)", s.Email)
	}

	origExpiration := s.ExpiresOn
	expires := time.Now().Add(duration).Truncate(time.Second)
	s.AccessToken = newToken
	s.IDToken = newIDToken
	s.ExpiresOn = &expires
	logger.Printf("refreshed access token %s (expired on %s)", s, origExpiration)
	return true, nil
}

func (p *GoogleProvider) redeemRefreshToken(ctx context.Context, refreshToken string) (token string, idToken string, expires time.Duration, err error) {
	// https://developers.google.com/identity/protocols/OAuth2WebServer#refresh
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return
	}

	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("refresh_token", refreshToken)
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
		UnmarshalInto(&data)
	if err != nil {
		return "", "", 0, err
	}

	token = data.AccessToken
	idToken = data.IDToken
	expires = time.Duration(data.ExpiresIn) * time.Second
	return
}
