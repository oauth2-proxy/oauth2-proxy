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
	p.getAuthorizationHeaderFunc = makeAzureHeader

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

func (p *AzureProvider) GetLoginURL(redirectURI, state, _ string) string {
	extraParams := url.Values{}
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		extraParams.Add("resource", p.ProtectedResource.String())
	}
	a := makeLoginURL(p.ProviderData, redirectURI, state, extraParams)
	return a.String()
}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *AzureProvider) Redeem(ctx context.Context, redirectURL, code string) (*sessions.SessionState, error) {
	params, err := p.prepareRedeem(redirectURL, code)
	if err != nil {
		return nil, err
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

	session := &sessions.SessionState{
		AccessToken:  jsonResponse.AccessToken,
		IDToken:      jsonResponse.IDToken,
		RefreshToken: jsonResponse.RefreshToken,
	}
	session.CreatedAtNow()
	session.SetExpiresOn(time.Unix(jsonResponse.ExpiresOn, 0))

	email, err := p.verifyTokenAndExtractEmail(ctx, session.IDToken, session.AccessToken)

	// https://github.com/oauth2-proxy/oauth2-proxy/pull/914#issuecomment-782285814
	// https://github.com/AzureAD/azure-activedirectory-library-for-java/issues/117
	// due to above issues, id_token may not be signed by AAD
	// in that case, we will fallback to access token
	if err == nil && email != "" {
		session.Email = email
	} else {
		logger.Printf("unable to get email claim from id_token: %v", err)
	}

	if session.Email == "" {
		email, err = p.verifyTokenAndExtractEmail(ctx, session.AccessToken, session.AccessToken)
		if err == nil && email != "" {
			session.Email = email
		} else {
			logger.Printf("unable to get email claim from access token: %v", err)
		}
	}

	return session, nil
}

// EnrichSession finds the email to enrich the session state
func (p *AzureProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	if s.Email != "" {
		return nil
	}

	email, err := p.getEmailFromProfileAPI(ctx, s.AccessToken)
	if err != nil {
		return fmt.Errorf("unable to get email address: %v", err)
	}
	if email == "" {
		return errors.New("unable to get email address")
	}
	s.Email = email

	return nil
}

func (p *AzureProvider) prepareRedeem(redirectURL, code string) (url.Values, error) {
	params := url.Values{}
	if code == "" {
		return params, ErrMissingCode
	}
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return params, err
	}

	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}
	return params, nil
}

// verifyTokenAndExtractEmail tries to extract email claim from either id_token or access token
// when oidc verifier is configured
func (p *AzureProvider) verifyTokenAndExtractEmail(ctx context.Context, rawIDToken string, accessToken string) (string, error) {
	email := ""

	if rawIDToken != "" && p.Verifier != nil {
		_, err := p.Verifier.Verify(ctx, rawIDToken)
		// due to issues mentioned above, id_token may not be signed by AAD
		if err == nil {
			s, err := p.buildSessionFromClaims(rawIDToken, accessToken)
			if err == nil {
				email = s.Email
			} else {
				logger.Printf("unable to get claims from token: %v", err)
			}
		} else {
			logger.Printf("unable to verify token: %v", err)
		}
	}

	return email, nil
}

// RefreshSession uses the RefreshToken to fetch new Access and ID Tokens
func (p *AzureProvider) RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if s == nil || s.RefreshToken == "" {
		return false, nil
	}

	err := p.redeemRefreshToken(ctx, s)
	if err != nil {
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	return true, nil
}

func (p *AzureProvider) redeemRefreshToken(ctx context.Context, s *sessions.SessionState) error {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return err
	}

	params := url.Values{}
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", clientSecret)
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
		return err
	}

	s.AccessToken = jsonResponse.AccessToken
	s.IDToken = jsonResponse.IDToken
	s.RefreshToken = jsonResponse.RefreshToken

	s.CreatedAtNow()
	s.SetExpiresOn(time.Unix(jsonResponse.ExpiresOn, 0))

	email, err := p.verifyTokenAndExtractEmail(ctx, s.IDToken, s.AccessToken)

	// https://github.com/oauth2-proxy/oauth2-proxy/pull/914#issuecomment-782285814
	// https://github.com/AzureAD/azure-activedirectory-library-for-java/issues/117
	// due to above issues, id_token may not be signed by AAD
	// in that case, we will fallback to access token
	if err == nil && email != "" {
		s.Email = email
	} else {
		logger.Printf("unable to get email claim from id_token: %v", err)
	}

	if s.Email == "" {
		email, err = p.verifyTokenAndExtractEmail(ctx, s.AccessToken, s.AccessToken)
		if err == nil && email != "" {
			s.Email = email
		} else {
			logger.Printf("unable to get email claim from access token: %v", err)
		}
	}

	return nil
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

	if err != nil || email == "" {
		email, err = json.Get("userPrincipalName").String()
		if err != nil {
			logger.Errorf("unable to find userPrincipalName: %s", err)
			return "", err
		}
	}

	return email, err
}

func (p *AzureProvider) getEmailFromProfileAPI(ctx context.Context, accessToken string) (string, error) {
	if accessToken == "" {
		return "", errors.New("missing access token")
	}

	json, err := requests.New(p.ProfileURL.String()).
		WithContext(ctx).
		WithHeaders(makeAzureHeader(accessToken)).
		Do().
		UnmarshalJSON()
	if err != nil {
		return "", err
	}

	return getEmailFromJSON(json)
}

// ValidateSession validates the AccessToken
func (p *AzureProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeAzureHeader(s.AccessToken))
}
