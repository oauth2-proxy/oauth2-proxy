package providers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/bitly/go-simplejson"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// AzureProvider represents an Azure based Identity Provider
type AzureProvider struct {
	*ProviderData
	Tenant string
}

var _ Provider = (*AzureProvider)(nil)

const (
	azureProviderName = "Azure"
	azureDefaultScope = "openid"
)

var (
	// Default Login URL for Azure.
	// Pre-parsed URL of https://login.microsoftonline.com/common/oauth2/authorize.
	azureDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "login.microsoftonline.com",
		Path:   "/common/oauth2/authorize",
	}

	// Default Redeem URL for Azure.
	// Pre-parsed URL of https://login.microsoftonline.com/common/oauth2/token.
	azureDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "login.microsoftonline.com",
		Path:   "/common/oauth2/token",
	}

	// Default Profile URL for Azure.
	// Pre-parsed URL of https://graph.microsoft.com/v1.0/me.
	azureDefaultProfileURL = &url.URL{
		Scheme: "https",
		Host:   "graph.microsoft.com",
		Path:   "/v1.0/me",
	}

	// Default ProtectedResource URL for Azure.
	// Pre-parsed URL of https://graph.microsoft.com.
	azureDefaultProtectResourceURL = &url.URL{
		Scheme: "https",
		Host:   "graph.microsoft.com",
	}
)

// NewAzureProvider initiates a new AzureProvider
func NewAzureProvider(p *ProviderData) *AzureProvider {
	p.setProviderDefaults(providerDefaults{
		name:        azureProviderName,
		loginURL:    azureDefaultLoginURL,
		redeemURL:   azureDefaultRedeemURL,
		profileURL:  azureDefaultProfileURL,
		validateURL: nil,
		scope:       azureDefaultScope,
	})

	if p.ProtectedResource == nil || p.ProtectedResource.String() == "" {
		p.ProtectedResource = azureDefaultProtectResourceURL
	}
	if p.ValidateURL == nil || p.ValidateURL.String() == "" {
		p.ValidateURL = p.ProfileURL
	}

	return &AzureProvider{
		ProviderData: p,
		Tenant:       "common",
	}
}

// Configure defaults the AzureProvider configuration options
func (p *AzureProvider) Configure(tenant string) {
	if tenant == "" || tenant == "common" {
		// tenant is empty or default, remain on the default "common" tenant
		return
	}

	// Specific tennant specified, override the Login and RedeemURLs
	p.Tenant = tenant
	overrideTenantURL(p.LoginURL, azureDefaultLoginURL, tenant, "authorize")
	overrideTenantURL(p.RedeemURL, azureDefaultRedeemURL, tenant, "token")
}

func overrideTenantURL(current, defaultURL *url.URL, tenant, path string) {
	if current == nil || current.String() == "" || current.String() == defaultURL.String() {
		*current = url.URL{
			Scheme: "https",
			Host:   "login.microsoftonline.com",
			Path:   "/" + tenant + "/oauth2/" + path}
	}
}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *AzureProvider) Redeem(ctx context.Context, redirectURL, code string) (*sessions.SessionState, error) {
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
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}

	// blindly try json and x-www-form-urlencoded
	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresOn    int64  `json:"expires_on,string"`
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

	created := time.Now()
	expires := time.Unix(jsonResponse.ExpiresOn, 0)

	return &sessions.SessionState{
		AccessToken:  jsonResponse.AccessToken,
		IDToken:      jsonResponse.IDToken,
		CreatedAt:    &created,
		ExpiresOn:    &expires,
		RefreshToken: jsonResponse.RefreshToken,
	}, nil
}

// RefreshSessionIfNeeded checks if the session has expired and uses the
// RefreshToken to fetch a new ID token if required
func (p *AzureProvider) RefreshSessionIfNeeded(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if s == nil || s.ExpiresOn.After(time.Now()) || s.RefreshToken == "" {
		return false, nil
	}

	origExpiration := s.ExpiresOn

	err := p.redeemRefreshToken(ctx, s)
	if err != nil {
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	fmt.Printf("refreshed id token %s (expired on %s)\n", s, origExpiration)
	return true, nil
}

func (p *AzureProvider) redeemRefreshToken(ctx context.Context, s *sessions.SessionState) (err error) {
	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("refresh_token", s.RefreshToken)
	params.Add("grant_type", "refresh_token")

	var jsonResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresOn    int64  `json:"expires_on,string"`
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
		return
	}

	now := time.Now()
	expires := time.Unix(jsonResponse.ExpiresOn, 0)
	s.AccessToken = jsonResponse.AccessToken
	s.IDToken = jsonResponse.IDToken
	s.RefreshToken = jsonResponse.RefreshToken
	s.CreatedAt = &now
	s.ExpiresOn = &expires
	return
}

func makeAzureHeader(accessToken string) http.Header {
	return makeAuthorizationHeader(tokenTypeBearer, accessToken, nil)
}

func getEmailFromJSON(json *simplejson.Json) (string, error) {
	var email string
	var err error

	email, err = json.Get("mail").String()

	if err != nil || email == "" {
		otherMails, otherMailsErr := json.Get("otherMails").Array()
		if len(otherMails) > 0 {
			email = otherMails[0].(string)
		}
		err = otherMailsErr
	}

	return email, err
}

// GetEmailAddress returns the Account email address
func (p *AzureProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	var email string
	var err error

	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}

	json, err := requests.New(p.ProfileURL.String()).
		WithContext(ctx).
		WithHeaders(makeAzureHeader(s.AccessToken)).
		Do().
		UnmarshalJSON()
	if err != nil {
		return "", err
	}

	email, err = getEmailFromJSON(json)
	if err == nil && email != "" {
		return email, err
	}

	email, err = json.Get("userPrincipalName").String()
	if err != nil {
		logger.Errorf("failed making request %s", err)
		return "", err
	}

	if email == "" {
		logger.Errorf("failed to get email address")
		return "", err
	}

	return email, err
}

func (p *AzureProvider) GetLoginURL(redirectURI, state string) string {
	extraParams := url.Values{}
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		extraParams.Add("resource", p.ProtectedResource.String())
	}
	a := makeLoginURL(p.ProviderData, redirectURI, state, extraParams)
	return a.String()
}

// ValidateSession validates the AccessToken
func (p *AzureProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeAzureHeader(s.AccessToken))
}
