package providers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/logger"
)

// ADFSProvider represents an ADFS based Identity Provider
type ADFSProvider struct {
	*ProviderData
}

type adfsClaims struct {
	Upn   string `json:"upn"`
	Email string `json:"email"`
}

// NewADFSProvider initiates a new ADFSProvider
func NewADFSProvider(p *ProviderData) *ADFSProvider {
	p.ProviderName = "ADFS"

	if p.Scope == "" {
		p.Scope = "openid"
	}
	return &ADFSProvider{ProviderData: p}
}

func adfsClaimsFromIDToken(idToken string) (*adfsClaims, error) {
	jwt := strings.Split(idToken, ".")
	jwtData := strings.TrimSuffix(jwt[1], "=")
	b, err := base64.RawURLEncoding.DecodeString(jwtData)
	if err != nil {
		return nil, err
	}

	c := &adfsClaims{}
	err = json.Unmarshal(b, c)
	if err != nil {
		return nil, err
	}
	if c.Email == "" {
		c.Email = c.Upn
	}
	return c, nil
}

// GetLoginURL overrides GetLoginURL to add ADFS parameters
func (p *ADFSProvider) GetLoginURL(redirectURI, state string) string {
	var a url.URL
	a = *p.LoginURL
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("redirect_uri", redirectURI)
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "code")
	params.Add("state", state)
	params.Add("resource", p.ProtectedResource.String())
	a.RawQuery = params.Encode()
	return a.String()
}

// Redeem exchanges the OAuth2 authentication token for an Access\ID tokens
func (p *ADFSProvider) Redeem(redirectURL, code string) (s *sessions.SessionState, err error) {
	if code == "" {
		err = errors.New("missing code")
		return
	}
	params := url.Values{}
	params.Add("grant_type", "authorization_code")
	params.Add("code", code)
	params.Add("client_id", p.ClientID)
	params.Add("redirect_uri", redirectURL)
	params.Add("resource", p.ProtectedResource.String())
	if p.ClientSecret != "" {
		params.Add("client_secret", p.ClientSecret)
	}
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
		IDToken      string `json:"id_token"`
	}
	err = json.Unmarshal(body, &jsonResponse)
	if err != nil {
		return
	}
	c, err := adfsClaimsFromIDToken(jsonResponse.IDToken)
	if err != nil {
		return
	}
	s = &sessions.SessionState{
		AccessToken:  jsonResponse.AccessToken,
		IDToken:      jsonResponse.IDToken,
		CreatedAt:    time.Now(),
		ExpiresOn:    time.Now().Add(time.Duration(jsonResponse.ExpiresIn) * time.Second).Truncate(time.Second),
		RefreshToken: jsonResponse.RefreshToken,
		Email:        c.Email,
		User:         c.Upn,
	}
	return
}

// RefreshSessionIfNeeded checks if the session has expired and uses the
// RefreshToken to fetch a new Access\ID tokens if required
func (p *ADFSProvider) RefreshSessionIfNeeded(s *sessions.SessionState) (bool, error) {
	if s == nil || s.ExpiresOn.After(time.Now()) || s.RefreshToken == "" {
		return false, nil
	}

	newToken, newIDToken, duration, err := p.redeemRefreshToken(s.RefreshToken)
	if err != nil {
		return false, err
	}

	origExpiration := s.ExpiresOn
	s.AccessToken = newToken
	s.IDToken = newIDToken
	s.ExpiresOn = time.Now().Add(duration).Truncate(time.Second)
	logger.Printf("refreshed access token %s (expired on %s)", s, origExpiration)
	return true, nil
}

func (p *ADFSProvider) redeemRefreshToken(refreshToken string) (token string, idToken string, expires time.Duration, err error) {
	params := url.Values{}
	params.Add("grant_type", "refresh_token")
	params.Add("resource", p.ProtectedResource.String())
	params.Add("client_id", p.ClientID)
	params.Add("refresh_token", refreshToken)
	if p.ClientSecret != "" {
		params.Add("client_secret", p.ClientSecret)
	}
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
		IDToken     string `json:"id_token"`
	}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return
	}
	token = data.AccessToken
	idToken = data.IDToken
	expires = time.Duration(data.ExpiresIn) * time.Second
	return
}
