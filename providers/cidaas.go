package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bitly/go-simplejson"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

type GroupsClaimList []GroupClaimEntry

type GroupClaimEntry struct {
	GroupID string   `json:"groupId"`
	Roles   []string `json:"roles"`
}

// CIDAASProvider represents an CIDAAS based Identity Provider
type CIDAASProvider struct {
	*OIDCProvider
}

var _ Provider = (*CIDAASProvider)(nil)

const (
	CidaasProviderName = "CIDAAS"
	CidaasGroupName    = "cidaas"
	CidaasDefaultScope = "openid email profile roles groups"
)

// NewCIDAASProvider initiates a new CIDAASProvider
func NewCIDAASProvider(p *ProviderData, opts options.Provider) *CIDAASProvider {
	p.setProviderDefaults(providerDefaults{
		name:  CidaasProviderName,
		scope: CidaasDefaultScope,
	})

	return &CIDAASProvider{
		OIDCProvider: NewOIDCProvider(p, opts.OIDCConfig),
	}
}

// RefreshSession uses the RefreshToken to fetch new Access and ID Tokens
func (p *CIDAASProvider) RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if s == nil || s.RefreshToken == "" {
		return false, nil
	}

	if err := p.redeemRefreshToken(ctx, s); err != nil {
		return false, fmt.Errorf("unable to redeem refresh token: %w", err)
	}

	if err := p.EnrichSession(ctx, s); err != nil {
		return false, fmt.Errorf("unable to enrich session data after refresh: %w %v", err, s)
	}

	return true, nil
}

// EnrichSession data to add email an groups
func (p *CIDAASProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	if p.ProfileURL.String() == "" && s.Email == "" {
		return errors.New("id_token did not contain an email and profileURL is not defined")
	} else if p.ProfileURL.String() == "" {
		return nil
	}

	// Try to get missing emails or groups from a profileURL
	if err := p.enrichFromUserinfoEndpoint(ctx, s); err != nil {
		logger.Errorf("Warning: Profile URL request failed: %s", err)
	}

	// If a mandatory email wasn't set, error at this point.
	if s.Email == "" {
		return errors.New("neither the id_token nor the profileURL set an email")
	}
	return nil
}

// enrichFromUserinfoEndpoint enriches a session's Email & Groups via the JSON response of
// an OIDC profile URL
func (p *CIDAASProvider) enrichFromUserinfoEndpoint(ctx context.Context, s *sessions.SessionState) error {
	// profile url is userinfo url in case of Cidaas
	respJSON, err := requests.New(p.ProfileURL.String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(s.AccessToken)).
		Do().
		UnmarshalSimpleJSON()
	if err != nil {
		return err
	}

	email, err := respJSON.Get(p.EmailClaim).String()
	if err == nil && s.Email == "" {
		s.Email = email
	}

	groups, err := p.extractGroups(respJSON)
	if err != nil {
		return fmt.Errorf("extracting groups failed: %w", err)
	}

	s.Groups = groups
	return nil
}

func (p *CIDAASProvider) extractGroups(respJSON *simplejson.Json) ([]string, error) {
	rawGroupsClaim, err := respJSON.Get(p.GroupsClaim).MarshalJSON()
	if err != nil {
		return nil, err
	}

	var groupsClaimList GroupsClaimList
	err = json.Unmarshal(rawGroupsClaim, &groupsClaimList)
	if err != nil {
		return nil, err
	}

	var groups []string
	for _, group := range groupsClaimList {
		for _, role := range group.Roles {
			groups = append(groups, fmt.Sprintf("%s:%s", group.GroupID, role))
		}
	}

	// Cidaas specific roles
	if rolesVal, rolesClaimExists := respJSON.CheckGet("roles"); rolesClaimExists {
		cidaasRoles, err := rolesVal.StringArray()
		if err != nil {
			return nil, fmt.Errorf("unmarshal roles failed: %w", err)
		}

		for _, role := range cidaasRoles {
			groups = append(groups, fmt.Sprintf("%s:%s", CidaasGroupName, role))
		}
	}

	return groups, nil
}
