package providers

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/requests"
)

type Auth0Provider struct {
	*ProviderData
	Domain string
}

func NewAuth0Provider(p *ProviderData) *Auth0Provider {
	p.ProviderName = "Auth0"
	p.Scope = "openid profile email"
	return &Auth0Provider{ProviderData: p}
}

func (p *Auth0Provider) Configure(domain string) {
	if domain == "" {
		panic(fmt.Sprintf("auth0 domain not set"))
	}
	p.Domain = domain
	p.LoginURL = &url.URL{
		Scheme: "https",
		Host: domain,
		Path: "/authorize",
	}
	p.RedeemURL = &url.URL{
		Scheme: "https",
		Host: domain,
		Path: "/oauth/token",
	}
	p.ProfileURL = &url.URL{
		Scheme: "https",
		Host: domain,
		Path: "/userinfo",
	}
	p.ValidateURL = p.ProfileURL
}

func (p *Auth0Provider) GetEmailAddress(s *sessions.SessionState) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}

	req, err := http.NewRequest("GET", p.ProfileURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header = getAuth0Header(s.AccessToken)

	var user struct {
		Email string `json:"email"`
	}

	err = requests.RequestJSON(req, &user)
	if err != nil {
		return "", err
	}

	if user.Email == "" {
		return "", errors.New("no email")
	}

	return user.Email, nil
}

func (p *Auth0Provider) GetLoginURL(redirectURI, state string) string {
	var a url.URL
	a = *p.LoginURL
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("redirect_uri", redirectURI)
	params.Set("approval_prompt", p.ApprovalPrompt)
	params.Add("scope", p.Scope)
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "code")
	params.Add("state", state)
	a.RawQuery = params.Encode()
	return a.String()
}

func (p *Auth0Provider) ValidateSessionState(s *sessions.SessionState) bool {
	return validateToken(p, s.AccessToken, getAuth0Header(s.AccessToken))
}

func getAuth0Header(accessToken string) http.Header {
	header := make(http.Header)
	header.Set("Accept", "application/json")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	return header
}
