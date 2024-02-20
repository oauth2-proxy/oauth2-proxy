package providers

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/exp/slices"

	"github.com/bitly/go-simplejson"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util"
)

// AzureProvider represents an Azure based Identity Provider
type AzureProvider struct {
	*ProviderData
	Tenant          string
	GraphGroupField string
	isV2Endpoint    bool
}

var _ Provider = (*AzureProvider)(nil)

const (
	azureProviderName           = "Azure"
	azureDefaultScope           = "openid"
	azureDefaultGraphGroupField = "id"
)

var (
	// Default Login URL for Azure. Pre-parsed URL of https://login.microsoftonline.com/common/oauth2/authorize.
	azureDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "login.microsoftonline.com",
		Path:   "/common/oauth2/authorize",
	}

	// Default Redeem URL for Azure. Pre-parsed URL of https://login.microsoftonline.com/common/oauth2/token.
	azureDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "login.microsoftonline.com",
		Path:   "/common/oauth2/token",
	}

	// Default Profile URL for Azure. Pre-parsed URL of https://graph.microsoft.com/v1.0/me.
	azureDefaultProfileURL = &url.URL{
		Scheme: "https",
		Host:   "graph.microsoft.com",
		Path:   "/v1.0/me",
	}
)

// NewAzureProvider initiates a new AzureProvider
func NewAzureProvider(p *ProviderData, opts options.AzureOptions) *AzureProvider {
	p.setProviderDefaults(providerDefaults{
		name:        azureProviderName,
		loginURL:    azureDefaultLoginURL,
		redeemURL:   azureDefaultRedeemURL,
		profileURL:  azureDefaultProfileURL,
		validateURL: nil,
		scope:       azureDefaultScope,
	})

	if p.ValidateURL == nil || p.ValidateURL.String() == "" {
		p.ValidateURL = p.ProfileURL
	}
	p.getAuthorizationHeaderFunc = makeAzureHeader

	tenant := "common"
	if opts.Tenant != "" {
		tenant = opts.Tenant
		overrideTenantURL(p.LoginURL, azureDefaultLoginURL, tenant, "authorize")
		overrideTenantURL(p.RedeemURL, azureDefaultRedeemURL, tenant, "token")
	}

	graphGroupField := azureDefaultGraphGroupField
	if opts.GraphGroupField != "" {
		graphGroupField = opts.GraphGroupField
	}

	isV2Endpoint := false
	if strings.Contains(p.LoginURL.String(), "v2.0") {
		isV2Endpoint = true
		azureV2GraphScope := fmt.Sprintf("https://%s/.default", p.ProfileURL.Host)

		if strings.Contains(p.Scope, " groups") {
			logger.Print("WARNING: `groups` scope is not an accepted scope when using Azure OAuth V2 endpoint. Removing it from the scope list")
			p.Scope = strings.ReplaceAll(p.Scope, " groups", "")
		}

		if !strings.Contains(p.Scope, " "+azureV2GraphScope) {
			// In order to be able to query MS Graph we must pass the ms graph default endpoint
			p.Scope += " " + azureV2GraphScope
		}

		if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
			logger.Print("WARNING: `--resource` option has no effect when using the Azure OAuth V2 endpoint.")
		}
	}

	return &AzureProvider{
		ProviderData:    p,
		Tenant:          tenant,
		GraphGroupField: graphGroupField,
		isV2Endpoint:    isV2Endpoint,
	}
}

func overrideTenantURL(current, defaultURL *url.URL, tenant, path string) {
	if current == nil || current.String() == "" || current.String() == defaultURL.String() {
		*current = url.URL{
			Scheme: "https",
			Host:   current.Host,
			Path:   "/" + tenant + "/oauth2/" + path}
	}
}

func getMicrosoftGraphGroupsURL(profileURL *url.URL, graphGroupField string) *url.URL {

	selectStatement := "$select=displayName,id"
	if !slices.Contains([]string{"displayName", "id"}, graphGroupField) {
		selectStatement += "," + graphGroupField
	}

	// Select only security groups. Due to the filter option, count param is mandatory even if unused otherwise
	return &url.URL{
		Scheme:   "https",
		Host:     profileURL.Host,
		Path:     "/v1.0/me/transitiveMemberOf",
		RawQuery: "$count=true&$filter=securityEnabled+eq+true&" + selectStatement,
	}
}

func (p *AzureProvider) GetLoginURL(redirectURI, state, _ string, extraParams url.Values) string {
	// In azure oauth v2 there is no resource param so add it only if V1 endpoint
	// https://docs.microsoft.com/en-us/azure/active-directory/azuread-dev/azure-ad-endpoint-comparison#scopes-not-resources
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" && !p.isV2Endpoint {
		extraParams.Add("resource", p.ProtectedResource.String())
	}
	a := makeLoginURL(p.ProviderData, redirectURI, state, extraParams)
	return a.String()
}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *AzureProvider) Redeem(ctx context.Context, redirectURL, code, codeVerifier string) (*sessions.SessionState, error) {
	params, err := p.prepareRedeem(redirectURL, code, codeVerifier)
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
		WithClient(p.Client).
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

	err = p.extractClaimsIntoSession(ctx, session)

	if err != nil {
		return nil, fmt.Errorf("unable to get email and/or groups claims from token: %v", err)
	}

	return session, nil
}

// EnrichSession enriches the session state with userID, mail and groups
func (p *AzureProvider) EnrichSession(ctx context.Context, session *sessions.SessionState) error {
	err := p.extractClaimsIntoSession(ctx, session)

	if err != nil {
		logger.Printf("unable to get email and/or groups claims from token: %v", err)
	}

	if session.Email == "" {
		email, err := p.getEmailFromProfileAPI(ctx, session.AccessToken)
		if err != nil {
			return fmt.Errorf("unable to get email address from profile URL: %v", err)
		}
		session.Email = email
	}

	// If using the v2.0 oidc endpoint we're also querying Microsoft Graph
	if p.isV2Endpoint {
		groups, err := p.getGroupsFromProfileAPI(ctx, session)
		if err != nil {
			return fmt.Errorf("unable to get groups from Microsoft Graph: %v", err)
		}
		session.Groups = util.RemoveDuplicateStr(append(session.Groups, groups...))
	}
	return nil
}

func (p *AzureProvider) prepareRedeem(redirectURL, code, codeVerifier string) (url.Values, error) {
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
	if codeVerifier != "" {
		params.Add("code_verifier", codeVerifier)
	}

	// In azure oauth v2 there is no resource param so add it only if V1 endpoint
	// https://docs.microsoft.com/en-us/azure/active-directory/azuread-dev/azure-ad-endpoint-comparison#scopes-not-resources
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" && !p.isV2Endpoint {
		params.Add("resource", p.ProtectedResource.String())
	}

	return params, nil
}

// extractClaimsIntoSession tries to extract email and groups claims from either id_token or access token
// when oidc verifier is configured
func (p *AzureProvider) extractClaimsIntoSession(ctx context.Context, session *sessions.SessionState) error {

	var s *sessions.SessionState

	// First let's verify session token
	if err := p.verifySessionToken(ctx, session); err != nil {
		return fmt.Errorf("unable to verify token: %v", err)
	}

	// https://github.com/oauth2-proxy/oauth2-proxy/pull/914#issuecomment-782285814
	// https://github.com/AzureAD/azure-activedirectory-library-for-java/issues/117
	// due to above issues, id_token may not be signed by AAD
	// in that case, we will fallback to access token
	var err error
	s, err = p.buildSessionFromClaims(session.IDToken, session.AccessToken)
	if err != nil || s.Email == "" {
		s, err = p.buildSessionFromClaims(session.AccessToken, session.AccessToken)
	}
	if err != nil {
		return fmt.Errorf("unable to get claims from token: %v", err)
	}

	session.Email = s.Email
	if s.Groups != nil {
		session.Groups = s.Groups
	}

	return nil
}

// verifySessionToken tries to validate id_token if present or access token when oidc verifier is configured
func (p *AzureProvider) verifySessionToken(ctx context.Context, session *sessions.SessionState) error {
	// Without a verifier there's no way to verify
	if p.Verifier == nil {
		return nil
	}

	if session.IDToken != "" {
		if _, err := p.Verifier.Verify(ctx, session.IDToken); err != nil {
			logger.Printf("unable to verify ID token, fallback to access token: %v", err)
			if _, err = p.Verifier.Verify(ctx, session.AccessToken); err != nil {
				return fmt.Errorf("unable to verify access token: %v", err)
			}
		}
	} else if _, err := p.Verifier.Verify(ctx, session.AccessToken); err != nil {
		return fmt.Errorf("unable to verify access token: %v", err)
	}
	return nil
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
		WithClient(p.Client).
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

	err = p.extractClaimsIntoSession(ctx, s)

	if err != nil {
		logger.Printf("unable to get email and/or groups claims from token: %v", err)
	}

	return nil
}

func makeAzureHeader(accessToken string) http.Header {
	return makeAuthorizationHeader(tokenTypeBearer, accessToken, nil)
}

func (p *AzureProvider) getGroupsFromProfileAPI(ctx context.Context, s *sessions.SessionState) ([]string, error) {
	if s.AccessToken == "" {
		return nil, fmt.Errorf("missing access token")
	}

	groupsURL := getMicrosoftGraphGroupsURL(p.ProfileURL, p.GraphGroupField).String()

	// Need and extra header while talking with MS Graph. For more context see
	// https://docs.microsoft.com/en-us/graph/api/group-list-transitivememberof?view=graph-rest-1.0&tabs=http#request-headers
	extraHeader := makeAzureHeader(s.AccessToken)
	extraHeader.Add("ConsistencyLevel", "eventual")

	var groups []string

	for groupsURL != "" {
		jsonRequest, err := requests.New(groupsURL).
			WithContext(ctx).
			WithClient(p.Client).
			WithHeaders(extraHeader).
			Do().
			UnmarshalSimpleJSON()
		if err != nil {
			return nil, fmt.Errorf("unable to unmarshal Microsoft Graph response: %v", err)

		}
		groupsURL, err = jsonRequest.Get("@odata.nextLink").String()
		if err != nil {
			groupsURL = ""
		}
		groupsPage := getGroupsFromJSON(jsonRequest, p.GraphGroupField)
		groups = append(groups, groupsPage...)
	}

	return groups, nil
}

func getGroupsFromJSON(json *simplejson.Json, graphGroupField string) []string {
	groups := []string{}

	for i := range json.Get("value").MustArray() {
		value := json.Get("value").GetIndex(i).Get(graphGroupField).MustString()
		groups = append(groups, value)
	}

	return groups
}

func (p *AzureProvider) getEmailFromProfileAPI(ctx context.Context, accessToken string) (string, error) {
	if accessToken == "" {
		return "", fmt.Errorf("missing access token")
	}

	json, err := requests.New(p.ProfileURL.String()).
		WithContext(ctx).
		WithClient(p.Client).
		WithHeaders(makeAzureHeader(accessToken)).
		Do().
		UnmarshalSimpleJSON()
	if err != nil {
		return "", err
	}

	email, err := getEmailFromJSON(json)
	if email == "" {
		return "", fmt.Errorf("empty email address: %v", err)
	}
	return email, nil
}

func getEmailFromJSON(json *simplejson.Json) (string, error) {
	email, err := json.Get("mail").String()

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

	return email, nil
}

// ValidateSession validates the AccessToken
func (p *AzureProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeAzureHeader(s.AccessToken))
}
