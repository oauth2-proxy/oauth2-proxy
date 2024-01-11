package providers

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
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
	isMultiTenant             bool
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

	isMultiTenant := false
	if strings.Contains(opts.OIDCConfig.IssuerURL, "https://login.microsoftonline.com/common/v2.0") {
		isMultiTenant = true
	}

	return &MicrosoftEntraIDProvider{
		OIDCProvider: NewOIDCProvider(p, opts.OIDCConfig),

		skipGraphGroups:           opts.MicrosoftEntraIDConfig.DisableGroupsFromGraph,
		isMultiTenant:             isMultiTenant,
		multiTenantAllowedTenants: opts.MicrosoftEntraIDConfig.AllowedMultiTenants,
		microsoftGraphURL:         microsoftGraphURL,
	}
}

// EnrichSession checks for group overage after calling generic EnrichSession
func (p *MicrosoftEntraIDProvider) EnrichSession(ctx context.Context, session *sessions.SessionState) error {
	err := p.OIDCProvider.EnrichSession(ctx, session)

	if !p.skipGraphGroups {
		hasGroupOverage, _ := p.checkGroupOverage(session)

		if hasGroupOverage {
			logger.Printf("entra overage found, reading groups from Graph API")
			if err = p.addGraphGroupsToSesion(ctx, session); err != nil {
				return fmt.Errorf("unable to read groups from graph: %v", err)
			}
		}
		logger.Printf("entra group overage not found")
	}

	return err
}

// ValidateSession checks for allowed tenants (e.g. for multi-tenant apps) and passes through to generic ValidateSession
func (p *MicrosoftEntraIDProvider) ValidateSession(ctx context.Context, session *sessions.SessionState) bool {

	if p.isMultiTenant {
		tenant, err := p.getTenantFromToken(session)
		if err != nil {
			logger.Errorf("unable to retrieve entra tenant from token: %v", err)
			return false
		}
		logger.Errorf("entra multi-tenant: issuer verified successfully, tenant: %s", tenant)
	}

	if len(p.multiTenantAllowedTenants) > 0 {
		tenant, err := p.getTenantFromToken(session)
		if err != nil {
			logger.Errorf("unable to retrieve entra tenant from token: %v", err)
			return false
		}

		tenantAllowed := p.checkTenantMatchesTenantList(tenant, p.multiTenantAllowedTenants)
		if !tenantAllowed {
			logger.Printf("entra: tenant %s is not specified in the list of allowed tenants", tenant)
			return false
		}
		logger.Printf("entra: tenant %s is allowed", tenant)
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

	groupsURL := fmt.Sprintf("%s/transitiveMemberOf?$select=id&$top=999", p.microsoftGraphURL)

	jsonRequest, err := requests.New(groupsURL).
		WithContext(ctx).
		WithHeaders(groupsHeaders).
		Do().
		UnmarshalSimpleJSON()

	if err != nil {
		return fmt.Errorf("unable to unmarshal Microsoft Graph response: %v", err)
	}

	reqGroups := jsonRequest.Get("value").MustArray()
	groups := make([]string, len(reqGroups))

	for i := range reqGroups {
		value := jsonRequest.Get("value").GetIndex(i).Get("id").MustString()
		groups = append(groups, value)
	}

	s.Groups = util.RemoveDuplicateStr(append(s.Groups, groups...))

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
