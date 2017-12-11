package providers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/googleapi"
)

type GoogleProvider struct {
	*ProviderData
	RedeemRefreshURL *url.URL
	// GroupValidator is a function that determines if the passed email is in
	// the configured Google group.
	GroupValidator func(string) bool
}

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

func emailFromIdToken(idToken string) (string, error) {

	// id_token is a base64 encode ID token payload
	// https://developers.google.com/accounts/docs/OAuth2Login#obtainuserinfo
	jwt := strings.Split(idToken, ".")
	b, err := base64.RawURLEncoding.DecodeString(jwt[1])
	if err != nil {
		return "", err
	}

	var email struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	err = json.Unmarshal(b, &email)
	if err != nil {
		return "", err
	}
	if email.Email == "" {
		return "", errors.New("missing email")
	}
	if !email.EmailVerified {
		return "", fmt.Errorf("email %s not listed as verified", email.Email)
	}
	return email.Email, nil
}

func (p *GoogleProvider) Redeem(redirectURL, code string) (s *SessionState, err error) {
	if code == "" {
		err = errors.New("missing code")
		return
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	var req *http.Request
	req, err = http.NewRequest("POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
		return
	}

	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		IdToken      string `json:"id_token"`
	}
	err = json.Unmarshal(body, &jsonResponse)
	if err != nil {
		return
	}
	var email string
	email, err = emailFromIdToken(jsonResponse.IdToken)
	if err != nil {
		return
	}
	s = &SessionState{
		AccessToken:  jsonResponse.AccessToken,
		ExpiresOn:    time.Now().Add(time.Duration(jsonResponse.ExpiresIn) * time.Second).Truncate(time.Second),
		RefreshToken: jsonResponse.RefreshToken,
		Email:        email,
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
		log.Fatal("can't read Google credentials file:", err)
	}
	conf, err := google.JWTConfigFromJSON(data, admin.AdminDirectoryUserReadonlyScope, admin.AdminDirectoryGroupReadonlyScope)
	if err != nil {
		log.Fatal("can't load Google credentials file:", err)
	}
	conf.Subject = adminEmail

	client := conf.Client(oauth2.NoContext)
	adminService, err := admin.New(client)
	if err != nil {
		log.Fatal(err)
	}
	return adminService
}

func userInGroup(service *admin.Service, groups []string, email string) bool {
	user, err := fetchUser(service, email)
	if err != nil {
		log.Printf("error fetching user: %v", err)
		return false
	}
	id := user.Id
	custID := user.CustomerId

	for _, group := range groups {
		members, err := fetchGroupMembers(service, group)
		if err != nil {
			if err, ok := err.(*googleapi.Error); ok && err.Code == 404 {
				log.Printf("error fetching members for group %s: group does not exist", group)
			} else {
				log.Printf("error fetching group members: %v", err)
				return false
			}
		}

		for _, member := range members {
			switch member.Type {
			case "CUSTOMER":
				if member.Id == custID {
					return true
				}
			case "USER":
				if member.Id == id {
					return true
				}
			}
		}
	}
	return false
}

func fetchUser(service *admin.Service, email string) (*admin.User, error) {
	user, err := service.Users.Get(email).Do()
	return user, err
}

func fetchGroupMembers(service *admin.Service, group string) ([]*admin.Member, error) {
	members := []*admin.Member{}
	pageToken := ""
	for {
		req := service.Members.List(group)
		if pageToken != "" {
			req.PageToken(pageToken)
		}
		r, err := req.Do()
		if err != nil {
			return nil, err
		}
		for _, member := range r.Members {
			members = append(members, member)
		}
		if r.NextPageToken == "" {
			break
		}
		pageToken = r.NextPageToken
	}
	return members, nil
}

// ValidateGroup validates that the provided email exists in the configured Google
// group(s).
func (p *GoogleProvider) ValidateGroup(s *SessionState) bool {
	return p.GroupValidator(s.Email)
}

func (p *GoogleProvider) RefreshSessionIfNeeded(s *SessionState) (bool, error) {
	if s == nil || s.ExpiresOn.After(time.Now()) || s.RefreshToken == "" {
		return false, nil
	}

	newToken, duration, err := p.redeemRefreshToken(s.RefreshToken)
	if err != nil {
		return false, err
	}

	// re-check that the user is in the proper google group(s)
	if !p.ValidateGroup(s) {
		return false, fmt.Errorf("%s is no longer in the group(s)", s.Email)
	}

	origExpiration := s.ExpiresOn
	s.AccessToken = newToken
	s.ExpiresOn = time.Now().Add(duration).Truncate(time.Second)
	log.Printf("refreshed access token %s (expired on %s)", s, origExpiration)
	return true, nil
}

func (p *GoogleProvider) redeemRefreshToken(refreshToken string) (token string, expires time.Duration, err error) {
	// https://developers.google.com/identity/protocols/OAuth2WebServer#refresh
	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("refresh_token", refreshToken)
	params.Add("grant_type", "refresh_token")
	var req *http.Request
	req, err = http.NewRequest("POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
		return
	}

	var data struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return
	}
	token = data.AccessToken
	expires = time.Duration(data.ExpiresIn) * time.Second
	return
}
