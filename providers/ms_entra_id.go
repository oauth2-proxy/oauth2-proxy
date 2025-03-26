package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util"
	"github.com/spf13/cast"
	"golang.org/x/oauth2"
	k8serrors "k8s.io/apimachinery/pkg/util/errors"
)

// MicrosoftEntraIDProvider represents provider for Azure Entra Authentication V2 endpoint
type MicrosoftEntraIDProvider struct {
	*OIDCProvider
	multiTenantAllowedTenants []string
	federatedTokenAuth        bool

	microsoftGraphURL *url.URL
}

const (
	microsoftEntraIDProviderName = "Microsoft Entra ID"
)

var (
	microsoftGraphURL = &url.URL{
		Scheme: "https",
		Host:   "graph.microsoft.com",
		Path:   "/v1.0/me",
	}
)

// NewMicrosoftEntraIDProvider initiates a new MicrosoftEntraIDProvider
func NewMicrosoftEntraIDProvider(p *ProviderData, opts options.Provider) *MicrosoftEntraIDProvider {
	p.setProviderDefaults(providerDefaults{
		name: microsoftEntraIDProviderName,
	})

	return &MicrosoftEntraIDProvider{
		OIDCProvider: NewOIDCProvider(p, opts.OIDCConfig),

		multiTenantAllowedTenants: opts.MicrosoftEntraIDConfig.AllowedTenants,
		federatedTokenAuth:        opts.MicrosoftEntraIDConfig.FederatedTokenAuth,
		microsoftGraphURL:         microsoftGraphURL,
	}
}

// EnrichSession checks for group overage after calling generic EnrichSession
func (p *MicrosoftEntraIDProvider) EnrichSession(ctx context.Context, session *sessions.SessionState) error {
	if err := p.OIDCProvider.EnrichSession(ctx, session); err != nil {
		return fmt.Errorf("unable to enrich session: %v", err)
	}

	return p.enrichSessionWithGroups(ctx, session)
}

func (p *MicrosoftEntraIDProvider) enrichSessionWithGroups(ctx context.Context, session *sessions.SessionState) error {
	hasGroupOverage, err := p.checkGroupOverage(session)
	if err != nil {
		return fmt.Errorf("unable to check token: %v", err)
	}

	if hasGroupOverage {
		logger.Printf("entra overage found, reading groups from Graph API")
		if err = p.addGraphGroupsToSession(ctx, session); err != nil {
			return fmt.Errorf("unable to enrich session: %v", err)
		}
	}
	return nil
}

// ValidateSession checks for allowed tenants (e.g. for multi-tenant apps) and passes through to generic ValidateSession
func (p *MicrosoftEntraIDProvider) ValidateSession(ctx context.Context, session *sessions.SessionState) bool {
	tenant, err := p.getTenantFromToken(session)
	if err != nil {
		logger.Errorf("unable to retrieve entra tenant from token: %v", err)
		return false
	}

	if len(p.multiTenantAllowedTenants) > 0 {
		tenantAllowed := p.checkTenantMatchesTenantList(tenant, p.multiTenantAllowedTenants)
		if !tenantAllowed {
			logger.Printf("entra: tenant %s is not specified in the list of allowed tenants", tenant)
			return false
		}
		logger.Printf("entra: tenant %s is allowed", tenant)
	}

	return p.OIDCProvider.ValidateSession(ctx, session)
}

// Redeem exchanges the OAuth2 authentication token for an ID token, considering federated token authentication
func (p *MicrosoftEntraIDProvider) Redeem(ctx context.Context, redirectURL, code, codeVerifier string) (*sessions.SessionState, error) {
	if p.federatedTokenAuth {
		return p.redeemWithFederatedToken(ctx, redirectURL, code, codeVerifier)
	}

	return p.OIDCProvider.Redeem(ctx, redirectURL, code, codeVerifier)
}

func (p *MicrosoftEntraIDProvider) CreateSessionFromToken(ctx context.Context, token string) (*sessions.SessionState, error) {
	if p.Verifier == nil && len(p.OIDCProvider.JWTVerifiers) == 0 {
		return nil, ErrNotImplemented
	}

	// As MS Entra ID need an extra group collection after session load, we need to
	// reproduce the logic from oauthproxy to get the session state
	errs := []error{errors.New("unable to verify bearer token from MS Entra ID provider")}
	if p.Verifier != nil {
		session, err := p.createSessionFromToken(ctx, token, p.Verifier.Verify)
		if err != nil {
			errs = append(errs, err)
		} else {
			return session, nil
		}
	}
	for _, verifier := range p.OIDCProvider.JWTVerifiers {
		session, err := p.createSessionFromToken(ctx, token, verifier.Verify)
		if err != nil {
			errs = append(errs, err)
			continue
		} else {
			return session, nil
		}
	}

	return nil, k8serrors.NewAggregate(errs)
}

func (p *MicrosoftEntraIDProvider) createSessionFromToken(ctx context.Context, token string, verify middleware.VerifyFunc) (*sessions.SessionState, error) {
	session, err := middleware.CreateTokenToSessionFunc(verify)(ctx, token)
	if err != nil {
		return nil, err
	}
	err = p.enrichSessionWithGroups(ctx, session)
	return session, err
}

// redeemWithFederatedToken performs custom token exchange with federated token instead of client secret
func (p *MicrosoftEntraIDProvider) redeemWithFederatedToken(ctx context.Context, redirectURL, code, codeVerifier string) (*sessions.SessionState, error) {
	federatedTokenPath := os.Getenv("AZURE_FEDERATED_TOKEN_FILE")
	federatedToken, err := os.ReadFile(federatedTokenPath)
	if err != nil {
		return nil, fmt.Errorf("error reading federated token file %s: %s", federatedTokenPath, err)
	}

	params := url.Values{}

	// create custom exchange parameters
	if codeVerifier != "" {
		params.Add("code_verifier", codeVerifier)
	}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_assertion", string(federatedToken))
	params.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")

	// perform exchange
	resp := requests.New(p.RedeemURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		WithBody(bytes.NewBufferString(params.Encode())).
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		Do()

	// prepare token of type *oauth2.Token
	var token *oauth2.Token
	var rawResponse interface{}

	body := resp.Body()
	if err := json.Unmarshal(body, &rawResponse); err != nil {
		return nil, err
	}

	if err := json.Unmarshal(body, &token); err != nil {
		return nil, err
	}

	// create session using new token and generic OIDC provider
	return p.OIDCProvider.createSession(ctx, token.WithExtra(rawResponse), false)
}

// checkGroupOverage checks ID token's group membership claims for the group overage
func (p *MicrosoftEntraIDProvider) checkGroupOverage(session *sessions.SessionState) (bool, error) {
	extractor, err := p.getClaimExtractor(session.IDToken, session.AccessToken)
	if err != nil {
		return false, fmt.Errorf("unable to get claim extractor: %v", err)
	}

	claimNames, _, _ := extractor.GetClaim("_claim_names")

	var claimNamesMap map[string]string

	if claimNames != nil {
		claimNamesMap = cast.ToStringMapString(claimNames)
	}

	if _, groupsKeyPresent := claimNamesMap["groups"]; groupsKeyPresent {
		return true, nil
	}

	return false, nil
}

func (p *MicrosoftEntraIDProvider) addGraphGroupsToSession(ctx context.Context, s *sessions.SessionState) error {
	groupsHeaders := makeAuthorizationHeader(tokenTypeBearer, s.AccessToken, nil)
	groupsHeaders.Add("ConsistencyLevel", "eventual")

	var allGroups []string
	var nextLink string

	for {
		if nextLink == "" {
			nextLink = fmt.Sprintf("%s/transitiveMemberOf?$select=id&$top=100", p.microsoftGraphURL)
		}

		response, err := requests.New(nextLink).
			WithContext(ctx).
			WithHeaders(groupsHeaders).
			Do().
			UnmarshalSimpleJSON()

		if err != nil {
			logger.Errorf("invalid response from microsoft graph, no groups added to session: %v", err)
			return nil
		}
		reqGroups := response.Get("value").MustArray()

		for i := range reqGroups {
			value := response.Get("value").GetIndex(i).Get("id").MustString()
			allGroups = append(allGroups, value)
		}

		// https://learn.microsoft.com/en-us/graph/paging?view=graph-rest-1.0&tabs=http#how-paging-works
		nextLink = response.Get("@odata.nextLink").MustString()

		if nextLink == "" {
			break
		}
	}

	s.Groups = util.RemoveDuplicateStr(append(s.Groups, allGroups...))
	return nil
}

func (p *MicrosoftEntraIDProvider) getTenantFromToken(session *sessions.SessionState) (string, error) {
	extractor, err := p.getClaimExtractor(session.IDToken, session.AccessToken)
	if err != nil {
		return "", fmt.Errorf("unable to get claim extractor: %v", err)
	}

	value, exists, err := extractor.GetClaim("iss")

	if !exists || err != nil {
		return "", fmt.Errorf("iss claim does not exist in the token")
	}

	pattern := `^https://login\.microsoftonline\.com/([a-zA-Z0-9-]+)/v2\.0$`
	re := regexp.MustCompile(pattern)

	matches := re.FindStringSubmatch(value.(string))

	if len(matches) > 1 {
		return matches[1], nil
	}

	return "", fmt.Errorf("invalid issuer in the ID token")
}

func (p *MicrosoftEntraIDProvider) checkTenantMatchesTenantList(tenant string, allowedTenantList []string) bool {
	for _, allowedTenant := range allowedTenantList {
		if tenant == allowedTenant {
			return true
		}
	}
	return false
}
