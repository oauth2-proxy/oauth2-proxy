package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/bitly/go-simplejson"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/requests"
)

// AzureProvider represents an Azure based Identity Provider
type AzureProvider struct {
	*ProviderData
	Tenant string
}

// NewAzureProvider initiates a new AzureProvider
func NewAzureProvider(p *ProviderData) *AzureProvider {
	p.ProviderName = "Azure"

	if p.ProfileURL == nil || p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{
			Scheme: "https",
			Host:   "graph.microsoft.com",
			Path:   "/v1.0/me",
		}
	}
	if p.ProtectedResource == nil || p.ProtectedResource.String() == "" {
		p.ProtectedResource = &url.URL{
			Scheme: "https",
			Host:   "graph.microsoft.com",
		}
	}
	if p.Scope == "" {
		p.Scope = "openid"
	}

	return &AzureProvider{ProviderData: p}
}

// Configure defaults the AzureProvider configuration options
func (p *AzureProvider) Configure(tenant string) {
	p.Tenant = tenant
	if tenant == "" {
		p.Tenant = "common"
	}

	if p.LoginURL == nil || p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   "login.microsoftonline.com",
			Path:   "/" + p.Tenant + "/oauth2/authorize"}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   "login.microsoftonline.com",
			Path:   "/" + p.Tenant + "/oauth2/token",
		}
	}
}

func (p *AzureProvider) Redeem(ctx context.Context, redirectURL, code string) (*sessions.SessionState, error) {
	if code == "" {
		return nil, errors.New("missing code")
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
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var resp *http.Response
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
	}

	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresOn    int64  `json:"expires_on,string"`
		IDToken      string `json:"id_token"`
	}
	err = json.Unmarshal(body, &jsonResponse)
	if err != nil {
		return nil, err
	}

	return &sessions.SessionState{
		AccessToken:  jsonResponse.AccessToken,
		IDToken:      jsonResponse.IDToken,
		CreatedAt:    time.Now(),
		ExpiresOn:    time.Unix(jsonResponse.ExpiresOn, 0),
		RefreshToken: jsonResponse.RefreshToken,
	}, nil
}

func getAzureHeader(accessToken string) http.Header {
	header := make(http.Header)
	header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	header.Set("Accept", "application/json")
	return header
}

func getEmailFromJSON(json *simplejson.Json) (string, error) {
	email, err := json.Get("mail").String()
	if err != nil || email == "" {
		otherMails, err := json.Get("otherMails").Array()
		if err != nil {
			return "", err
		}
		if len(otherMails) == 0 {
			return "", errors.New("no email")
		}
		email, ok := otherMails[0].(string)
		if !ok {
			return "", errors.New("no email")
		}
		return email, nil
	}

	return email, nil
}

// GetEmailAddress returns the Account email address
func (p *AzureProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.ProfileURL.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header = getAzureHeader(s.AccessToken)

	json, err := requests.Request(req)
	if err != nil {
		return "", err
	}

	email, err := getEmailFromJSON(json)
	if err == nil && email != "" {
		return email, err
	}

	email, err = json.Get("userPrincipalName").String()
	if err != nil {
		logger.Printf("failed making request %s", err)
		return "", err
	}

	if email == "" {
		logger.Printf("failed to get email address")
		return "", err
	}

	return email, nil
}
