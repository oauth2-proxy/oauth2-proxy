package providers

import (
	"context"
	"fmt"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// NextcloudProvider represents an Nextcloud based Identity Provider
type NextcloudProvider struct {
	*ProviderData
}

var _ Provider = (*NextcloudProvider)(nil)

const nextCloudProviderName = "Nextcloud"

// NewNextcloudProvider initiates a new NextcloudProvider
func NewNextcloudProvider(p *ProviderData) *NextcloudProvider {
	p.setProviderDefaults(providerDefaults{
		name: nextCloudProviderName,
	})

	p.getAuthorizationHeaderFunc = makeOIDCHeader
	if p.EmailClaim == options.OIDCEmailClaim {
		// This implies the email claim has not been overridden, we should set a default
		// for this provider
		p.EmailClaim = "ocs.data.email"
	}
	return &NextcloudProvider{ProviderData: p}
}

// EnrichSession uses the Nextcloud userinfo endpoint to populate
// the session's email, user, and groups.
func (p *NextcloudProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	// Fallback to ValidateURL if ProfileURL not set for legacy compatibility
	profileURL := p.ValidateURL.String()
	if p.ProfileURL.String() != "" {
		profileURL = p.ProfileURL.String()
	}

	json, err := requests.New(profileURL).
		WithContext(ctx).
		WithClient(p.Client).
		SetHeader("Authorization", tokenTypeBearer+" "+s.AccessToken).
		Do().
		UnmarshalSimpleJSON()
	if err != nil {
		logger.Errorf("failed making request %v", err)
		return err
	}

	groups, err := json.GetPath("ocs", "data", "groups").StringArray()
	if err == nil {
		for _, group := range groups {
			if group != "" {
				s.Groups = append(s.Groups, group)
			}
		}
	}

	user, err := json.GetPath("ocs", "data", "id").String()
	if err != nil {
		return fmt.Errorf("unable to extract id from userinfo endpoint: %v", err)
	}
	s.User = user

	email, err := json.GetPath("ocs", "data", "email").String()
	if err != nil {
		return fmt.Errorf("unable to extract email from userinfo endpoint: %v", err)
	}
	s.Email = email

	return nil
}

// ValidateSession validates the AccessToken
func (p *NextcloudProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
}
