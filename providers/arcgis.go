package providers

import (
	"context"
	"fmt"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// ArcgisProvider represents an ArcGIS based Identity Provider
type ArcgisProvider struct {
	*ProviderData
}

type arcgisGroups []struct {
	Id string `json:"id"`
}

type arcgisUserinfo struct {
	Username string       `json:"username"`
	Email    string       `json:"email"`
	Fullname string       `json:"fullName"`
	Groups   arcgisGroups `json:"groups"`
}

var _ Provider = (*ArcgisProvider)(nil)

const (
	arcgisProviderName = "Arcgis"
)

var (
	// Default Login URL for ArcGIS.
	// Pre-parsed URL of https://www.arcgis.com/sharing/rest/oauth2/authorize.
	arcgisDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "www.arcgis.com",
		Path:   "/sharing/rest/oauth2/authorize",
	}

	// Default Redeem URL for ArcGIS.
	// Pre-parsed URL of https://wwww.arcgis.com/sharing/rest/oauth2/token.
	arcgisDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "www.arcgis.com",
		Path:   "/sharing/rest/oauth2/token",
	}

	// Validate URL for ArcGIS.
	// Pre-parsed URL of https://www.arcgis.com/sharing/rest/community/self?f=json.
	arcgisValidateURL = &url.URL{
		Scheme: "https",
		Host:   "www.arcgis.com",
		Path:   "/sharing/rest/community/self",
	}
)

// NewArcgisProvider initiates a new ArcgisProvider
func NewArcgisProvider(p *ProviderData) *ArcgisProvider {
	p.setProviderDefaults(providerDefaults{
		name:        arcgisProviderName,
		loginURL:    arcgisDefaultLoginURL,
		redeemURL:   arcgisDefaultRedeemURL,
		validateURL: arcgisValidateURL,
	})
	// ArcGIS ValidateURL requires json output to be forced
	p.ValidateURL.RawQuery = "f=json"
	return &ArcgisProvider{ProviderData: p}
}

// GetUserInfo returns the arcgisUserinfo
func (p *ArcgisProvider) GetUserInfo(ctx context.Context, s *sessions.SessionState) (*arcgisUserinfo, error) {
	var userinfo arcgisUserinfo

	err := requests.New(p.ValidateURL.String()).
		WithContext(ctx).
		SetHeader("Authorization", tokenTypeBearer+" "+s.AccessToken).
		Do().
		UnmarshalInto(&userinfo)
	if err != nil {
		return nil, fmt.Errorf("error getting user info: %v", err)
	}

	return &userinfo, nil
}

// EnrichSession updates the Username, Email, Fullname and Groups after the initial Redeem
func (p *ArcgisProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	// Retrieve user info
	userinfo, err := p.GetUserInfo(ctx, s)
	if err != nil {
		return fmt.Errorf("failed to retrieve user info: %v", err)
	}
	if userinfo.Username != "" {
		s.User = userinfo.Username
	}
	if userinfo.Email != "" {
		s.Email = userinfo.Email
	}
	if userinfo.Fullname != "" {
		s.PreferredUsername = userinfo.Fullname
	}
	if len(userinfo.Groups) > 0 {
		for _, group := range userinfo.Groups {
			if group.Id != "" {
				s.Groups = append(s.Groups, group.Id)
			}
		}
	}
	return nil
}

// ValidateSession validates the AccessToken
func (p *ArcgisProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeAuthorizationHeader(tokenTypeBearer, s.AccessToken, nil))
}
