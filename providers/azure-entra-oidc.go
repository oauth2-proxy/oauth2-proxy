package providers

import (
	"context"
	"fmt"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util"
	"github.com/spf13/cast"
)

// AzureEntraOIDCProvider represents provider for Azure Entra Authentication V2 endpoint
type AzureEntraOIDCProvider struct {
	*OIDCProvider
	isMultiTenant             bool
	skipGraphGroups           bool
	multiTenantAllowedTenants []string
}

const (
	azureEntraOIDCProviderName = "Azure Entra OIDC"
	azureEntraOIDCGroupsURL    = "https://graph.microsoft.com/v1.0/me/transitiveMemberOf?$count=true&$filter=securityEnabled+eq+true&$select=id"
)

// NewAzureProvider initiates a new AzureProvider
func NewAzureEntraOIDCProvider(p *ProviderData, opts options.Provider) *AzureEntraOIDCProvider {
	// TODO: Add validation for issuer URL to be https://login.microsoftonline.com/{tenant or common}/v2.0
	p.setProviderDefaults(providerDefaults{
		name: azureEntraOIDCProviderName,
	})

	return &AzureEntraOIDCProvider{
		OIDCProvider:              NewOIDCProvider(p, opts.OIDCConfig),
		isMultiTenant:             strings.Contains(opts.OIDCConfig.IssuerURL, "common"),
		skipGraphGroups:           opts.AzureEntraOIDCConfig.DisableGroupsFromGraph,
		multiTenantAllowedTenants: opts.AzureEntraOIDCConfig.MultiTenantAllowedTenants,
	}
}

// EnrichSession checks for group overage and passes through to generic EnrichSession()
func (p *AzureEntraOIDCProvider) EnrichSession(ctx context.Context, session *sessions.SessionState) error {
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

// ValidateSession checks for allowed tenants for multi-tenant apps and passes through to generic ValidateSession
func (p *AzureEntraOIDCProvider) ValidateSession(ctx context.Context, session *sessions.SessionState) bool {

	if p.isMultiTenant {
		issuer, exists, error := p.getIssuer(session)
		if issuer == "" || !exists || error != nil {
			return false
		}

		if p.multiTenantAllowedTenants != nil {
			logger.Printf("List of allowed tenant is specified, we check if %s is allowed issuer", issuer)
			tenantAllowed := p.checkIssuerMatchesTenantList(issuer, p.multiTenantAllowedTenants)
			if !tenantAllowed {
				return false
			}
		}
	}

	return p.OIDCProvider.ValidateSession(ctx, session)
}

// checkGroupOverage checks is claims present in ID Token indicate group overage
func (p *AzureEntraOIDCProvider) checkGroupOverage(session *sessions.SessionState) (bool, error) {
	extractor, err := p.getClaimExtractor(session.IDToken, session.AccessToken)
	if err != nil {
		return false, fmt.Errorf("unable to get claim extractor: %v", err)
	}

	claimNames, _, _ := extractor.GetClaim("_claim_names")
	hasGroups, _, _ := extractor.GetClaim("hasGroups")

	if claimNames == nil && hasGroups == nil {
		return false, nil
	}

	var claimNamesMap map[string]string

	if claimNames != nil {
		claimNamesMap = cast.ToStringMapString(claimNames)
	} else {
		claimNamesMap = cast.ToStringMapString(hasGroups)
	}

	if _, groupsKeyPresent := claimNamesMap["groups"]; groupsKeyPresent {
		return true, nil
	}

	return false, nil
}

func (p *AzureEntraOIDCProvider) addGraphGroupsToSesion(ctx context.Context, s *sessions.SessionState) error {

	groupsHeaders := makeAuthorizationHeader(tokenTypeBearer, s.AccessToken, nil)
	groupsHeaders.Add("ConsistencyLevel", "eventual")

	jsonRequest, err := requests.New(azureEntraOIDCGroupsURL).WithContext(ctx).WithHeaders(groupsHeaders).Do().UnmarshalSimpleJSON()
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

func (p *AzureEntraOIDCProvider) getIssuer(session *sessions.SessionState) (string, bool, error) {
	extractor, err := p.getClaimExtractor(session.IDToken, session.AccessToken)
	if err != nil {
		return "", false, fmt.Errorf("unable to get claim extractor: %v", err)
	}

	value, exists, error := extractor.GetClaim("iss")
	return value.(string), exists, error
}

func (p *AzureEntraOIDCProvider) checkIssuerMatchesTenantList(issuer string, tenantList []string) bool {
	for _, tenant := range tenantList {
		if strings.Contains(issuer, tenant) {
			logger.Printf("Issuer %s found in the list of allowed tenants for multi-tenant apps, passing", issuer)
			return true
		}
	}
	logger.Printf("Issuer %s not found in the list of tenants for multi-tenant apps, denying", issuer)
	return false
}
