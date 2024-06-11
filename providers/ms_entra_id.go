package providers

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util"
	"github.com/spf13/cast"
)

// MicrosoftEntraIDProvider represents provider for Azure Entra Authentication V2 endpoint
type MicrosoftEntraIDProvider struct {
	*OIDCProvider
	skipGraphGroups           bool
	multiTenantAllowedTenants []string

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

		skipGraphGroups:           opts.MicrosoftEntraIDConfig.DisableGroupsFromGraph,
		multiTenantAllowedTenants: opts.MicrosoftEntraIDConfig.AllowedMultiTenants,
		microsoftGraphURL:         microsoftGraphURL,
	}
}

// EnrichSession checks for group overage and passes through to generic EnrichSession()
func (p *MicrosoftEntraIDProvider) EnrichSession(ctx context.Context, session *sessions.SessionState) error {
	err := p.OIDCProvider.EnrichSession(ctx, session)

	if !p.skipGraphGroups {
		logger.Printf("checking for overage of azure groups")
		hasGroupOverage, _ := p.checkGroupOverage(session)

		if hasGroupOverage {
			logger.Printf("overage found, reading groups from graph")
			if err = p.addGraphGroupsToSesion(ctx, session); err != nil {
				return fmt.Errorf("unable to read groups from graph: %v", err)
			}
		}
	}

	return err
}

// ValidateSession checks for allowed tenants (e.g. for multi-tenant apps) and passes through to generic ValidateSession
func (p *MicrosoftEntraIDProvider) ValidateSession(ctx context.Context, session *sessions.SessionState) bool {

	if len(p.multiTenantAllowedTenants) > 0 {
		issuer, exists, error := p.getIssuer(session)
		if issuer == "" || !exists || error != nil {
			return false
		}

		logger.Printf("List of allowed tenants is specified, we check if %s is allowed issuer", issuer)
		tenantAllowed := p.checkIssuerMatchesTenantList(issuer, p.multiTenantAllowedTenants)
		if !tenantAllowed {
			return false
		}
	}

	return p.OIDCProvider.ValidateSession(ctx, session)
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

func (p *MicrosoftEntraIDProvider) addGraphGroupsToSesion(ctx context.Context, s *sessions.SessionState) error {

	groupsHeaders := makeAuthorizationHeader(tokenTypeBearer, s.AccessToken, nil)
	groupsHeaders.Add("ConsistencyLevel", "eventual")

	groupsURL := fmt.Sprintf("%s/transitiveMemberOf?$select=id", p.microsoftGraphURL)

	jsonRequest, err := requests.New(groupsURL).
		WithContext(ctx).
		WithHeaders(groupsHeaders).
		Do().
		UnmarshalSimpleJSON()

	if err != nil {
		return fmt.Errorf("unable to unmarshal Microsoft Graph response: %v", err)
	}

	var groups []string
	for i := range jsonRequest.Get("value").MustArray() {
		value := jsonRequest.Get("value").GetIndex(i).Get("id").MustString()
		groups = append(groups, value)
	}

	s.Groups = util.RemoveDuplicateStr(append(s.Groups, groups...))

	return nil
}

func (p *MicrosoftEntraIDProvider) getIssuer(session *sessions.SessionState) (string, bool, error) {
	extractor, err := p.getClaimExtractor(session.IDToken, session.AccessToken)
	if err != nil {
		return "", false, fmt.Errorf("unable to get claim extractor: %v", err)
	}

	value, exists, error := extractor.GetClaim("iss")
	return value.(string), exists, error
}

func (p *MicrosoftEntraIDProvider) checkIssuerMatchesTenantList(issuer string, tenantList []string) bool {
	for _, tenant := range tenantList {
		if strings.Contains(issuer, tenant) {
			logger.Printf("Issuer %s found in the list of allowed tenants for multi-tenant apps, passing", issuer)
			return true
		}
	}
	logger.Printf("Issuer %s not found in the list of tenants for multi-tenant apps, denying", issuer)
	return false
}
