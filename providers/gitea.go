package providers

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"io/ioutil"
	"net/http"
	"net/url"
)

// GiteaProvider represents an Gitea based Identity Provider
type GiteaProvider struct {
	*ProviderData
	user string
}

// NewGiteaProvider initiates a new GiteaProvider
func NewGiteaProvider(p *ProviderData) *GiteaProvider {
	p.ProviderName = "Gitea"
	if p.LoginURL == nil || p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   "gitea.com",
			Path:   "/login/oauth/authorize",
		}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   "gitea.com",
			Path:   "/login/oauth/access_token",
		}
	}
	// ValidationURL is the API Base URL
	if p.ValidateURL == nil || p.ValidateURL.String() == "" {
		p.ValidateURL = &url.URL{
			Scheme: "https",
			Host:   "api.gitea.com",
			Path:   "/",
		}
	}

	if p.Scope == "" {
		p.Scope = "user:email"
	}

	return &GiteaProvider{ProviderData: p}
}

func (p *GiteaProvider) SetUser(user string) {
	p.user = user
}

type giteaUserInfo struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}

var InvalidUserError error = errors.New("invalid username")

func (p *GiteaProvider) getUserInfo(s *sessions.SessionState) (*giteaUserInfo, error) {

	if s.AccessToken == "" {
		return nil, errors.New("missing access token")
	}

	// Build user info url from login url of Gitea instance
	userInfoURL := *p.LoginURL
	userInfoURL.Path = "/api/v1/user"

	req, err := http.NewRequest("GET", userInfoURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user info request: %v", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.AccessToken))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform user info request: %v", err)
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to read user info response: %v", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("got %d during user info request: %s", resp.StatusCode, body)
	}

	var userInfo giteaUserInfo
	err = json.Unmarshal(body, &userInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user info: %v", err)
	}

	if p.user != "" && p.user != userInfo.Username {
		fmt.Println(userInfo)
		return nil, fmt.Errorf("%w:%s", InvalidUserError, userInfo.Username)
	}

	return &userInfo, nil
}

func (p *GiteaProvider) GetEmailAddress(s *sessions.SessionState) (string, error) {

	userInfo, err := p.getUserInfo(s)
	if err != nil {
		return "", err
	}

	return userInfo.Email, nil
}

func (p *GiteaProvider) GetUserName(s *sessions.SessionState) (string, error) {
	userInfo, err := p.getUserInfo(s)
	if errors.Is(err, InvalidUserError) {
		return "", nil
	}
	if err != nil {
		return "", err
	}

	return userInfo.Username, nil
}
