package providers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	abstractions "github.com/microsoft/kiota-abstractions-go"
	"github.com/microsoft/kiota-abstractions-go/authentication"
	msgraphsdk "github.com/microsoftgraph/msgraph-sdk-go"
	msgraphcore "github.com/microsoftgraph/msgraph-sdk-go-core"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"github.com/microsoftgraph/msgraph-sdk-go/users"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
	"github.com/spf13/cast"
)

// AzureProvider represents an Azure based Identity Provider
type AzureProvider struct {
	*ProviderData
	Tenant          string
	GraphGroupField string
	graphClient     *msgraphsdk.GraphServiceClient
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
		Path:   "/common/oauth2/v2.0/authorize",
	}

	// Default Redeem URL for Azure. Pre-parsed URL of https://login.microsoftonline.com/common/oauth2/token.
	azureDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "login.microsoftonline.com",
		Path:   "/common/oauth2/v2.0/token",
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

	// Set up Graph client. Pass an anonymous authentication provider to the Graph
	// client as we'll be passing the access token in the request headers.
	adapter, _ := msgraphsdk.NewGraphRequestAdapter(&authentication.AnonymousAuthenticationProvider{})

	return &AzureProvider{
		ProviderData:    p,
		Tenant:          tenant,
		GraphGroupField: graphGroupField,
		graphClient:     msgraphsdk.NewGraphServiceClient(adapter),
	}
}

func overrideTenantURL(current, defaultURL *url.URL, tenant, path string) {
	if current == nil || current.String() == "" || current.String() == defaultURL.String() {
		*current = url.URL{
			Scheme: "https",
			Host:   "login.microsoftonline.com",
			Path:   "/" + tenant + "/oauth2/v2.0/" + path}
	}
}

func (p *AzureProvider) GetLoginURL(redirectURI, state, _ string, extraParams url.Values) string {
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

	return session, nil
}

// EnrichSession enriches the session state with userID, mail and groups
func (p *AzureProvider) EnrichSession(ctx context.Context, session *sessions.SessionState) error {
	err := p.extractClaimsIntoSession(ctx, session)

	if err != nil {
		return fmt.Errorf("unable to get email and/or groups claims from token: %v", err)
	}

	if session.Email == "" {
		email, err := p.getEmailFromProfileAPI(ctx, session.AccessToken)
		if err != nil {
			return fmt.Errorf("unable to get email address from profile URL: %v", err)
		}
		session.Email = email
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

	var err error
	s, err = p.buildSessionFromClaims(session.IDToken, session.AccessToken)
	if err != nil {
		return fmt.Errorf("unable to get claims from token: %v", err)
	}

	session.Email = s.Email

	// process groups claim and check for group overage
	var groupOverage bool
	if s.Groups != nil {
		session.Groups = s.Groups
	} else {
		// Check for group overage
		// https://learn.microsoft.com/en-us/azure/active-directory/external-identities/customers/how-to-web-app-role-based-access-control#handle-groups-overage
		// https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles#group-overages
		extractor, err := p.getClaimExtractor(session.IDToken, session.AccessToken)
		if err != nil {
			return fmt.Errorf("unable to get claim extractor: %v", err)
		}
		claimNames, exists, err := extractor.GetClaim("_claim_names")
		if err != nil {
			return fmt.Errorf("unable to extract _claim_names from token: %v", err)
		}
		if exists {
			claimNamesMap := cast.ToStringMapString(claimNames)
			// if the _claim_names claim exists, and it has a "groups" entry, we should query the Graph API
			_, groupOverage = claimNamesMap["groups"]
		}
		// implicit flow overage indication uses the "hasgroups" claim, so check for its existence as well
		if !groupOverage {
			var err error
			_, groupOverage, err = extractor.GetClaim("hasgroups")
			if err != nil {
				return fmt.Errorf("unable to extract hasgroups from token: %v", err)
			}
		}
	}

	if groupOverage || (session.Groups != nil && strings.EqualFold(p.GraphGroupField, "displayName")) {
		groupsMap, err := p.getGroupsFromProfileAPI(ctx, session.AccessToken)
		if err != nil {
			return fmt.Errorf("unable to get groups from Microsoft Graph: %v", err)
		}
		// if we have groups from the token, and we're here, we need to translate group
		// IDs to display names
		if session.Groups != nil {
			for key, group := range session.Groups {
				if displayName, ok := groupsMap[group]; ok {
					session.Groups[key] = displayName
				}
			}
		} else { // Process the group overage
			session.Groups = make([]string, 0)
			if strings.EqualFold(p.GraphGroupField, "displayName") {
				for _, displayName := range groupsMap {
					session.Groups = append(session.Groups, displayName)
				}
			} else {
				for group := range groupsMap {
					session.Groups = append(session.Groups, group)
				}
			}
		}
	}
	sort.Strings(session.Groups)

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

func makeGraphAuthHeader(accessToken string) *abstractions.RequestHeaders {
	headers := abstractions.NewRequestHeaders()
	headers.Add("Authorization", makeAzureHeader(accessToken).Get("Authorization"))
	return headers
}

func (p *AzureProvider) getGroupsFromProfileAPI(ctx context.Context, accessToken string) (map[string]string, error) {
	groups := make(map[string]string)

	// Query Graph API for user's groups
	// https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles#group-overages
	// https://learn.microsoft.com/en-us/graph/api/user-list-transitivememberof?view=graph-rest-1.0&tabs=go
	groupsResponse, err := p.graphClient.Me().TransitiveMemberOf().GraphGroup().Get(ctx, &users.ItemTransitiveMemberOfGraphGroupRequestBuilderGetRequestConfiguration{Headers: makeGraphAuthHeader(accessToken)})
	if err != nil {
		return nil, fmt.Errorf("unable to query user's groups from Microsoft Graph API: %v", getOdataError(err))
	}
	// Use PageIterator to iterate through all groups
	pageIterator, err := msgraphcore.NewPageIterator[models.Groupable](groupsResponse, p.graphClient.GetAdapter(), models.CreateGroupCollectionResponseFromDiscriminatorValue)
	// Set the authorization header for the page iterator
	pageIterator.SetHeaders(makeGraphAuthHeader(accessToken))
	err = pageIterator.Iterate(ctx, func(groupObj models.Groupable) bool {
		var (
			groupID     *string
			displayName *string
		)
		groupID = groupObj.GetId()
		displayName = groupObj.GetDisplayName()
		// if displayName is nil, the GroupMember.Read.All delegated permission has not
		// been granted, so use the group ID instead
		if displayName == nil {
			displayName = groupID
		}
		groups[*groupID] = *displayName
		return true
	})
	if err != nil {
		return nil, fmt.Errorf("unable to iterate through user's groups from Microsoft Graph API: %v", err)
	}

	return groups, nil
}

func (p *AzureProvider) getEmailFromProfileAPI(ctx context.Context, accessToken string) (string, error) {
	// Query Graph API for user's profile
	// https://learn.microsoft.com/en-us/graph/api/user-list-transitivememberof?view=graph-rest-1.0&tabs=go
	profileResponse, err := p.graphClient.Me().Get(ctx, &users.UserItemRequestBuilderGetRequestConfiguration{Headers: makeGraphAuthHeader(accessToken)})
	if err != nil {
		return "", fmt.Errorf("unable to query user's profile from Microsoft Graph API: %v", getOdataError(err))
	}
	if profileResponse.GetMail() != nil {
		return *profileResponse.GetMail(), nil
	}
	if profileResponse.GetOtherMails() != nil && len(profileResponse.GetOtherMails()) > 0 {
		return (profileResponse.GetOtherMails())[0], nil
	}
	if profileResponse.GetUserPrincipalName() != nil {
		return *profileResponse.GetUserPrincipalName(), nil
	}
	return "", fmt.Errorf("unable to find email address in user's profile from Microsoft Graph API")
}

func getOdataError(err error) error {
	var outErr error
	var ODataError *odataerrors.ODataError
	switch {
	case errors.As(err, &ODataError):
		var typed *odataerrors.ODataError
		errors.As(err, &typed)
		if terr := typed.GetErrorEscaped(); terr != nil {
			outErr = fmt.Errorf("%v: (%v) %v", typed.Error(), *terr.GetCode(), *terr.GetMessage())
		}
	default:
		outErr = fmt.Errorf("%T > error: %#v", err, err)
	}
	return outErr
}

// ValidateSession validates the AccessToken
func (p *AzureProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeAzureHeader(s.AccessToken))
}
