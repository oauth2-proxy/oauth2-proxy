package providers

import (
	"context"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

// NextcloudProvider represents an Nextcloud based Identity Provider
type NextcloudProvider struct {
	*ProviderData
}

var _ Provider = (*NextcloudProvider)(nil)

const nextCloudProviderName = "Nextcloud"

// NewNextcloudProvider initiates a new NextcloudProvider
func NewNextcloudProvider(p *ProviderData) *NextcloudProvider {
	p.ProviderName = nextCloudProviderName
	p.getAuthorizationHeaderFunc = makeOIDCHeader
	if p.EmailClaim == options.OIDCEmailClaim {
		// This implies the email claim has not been overridden, we should set a default
		// for this provider
		p.EmailClaim = "ocs.data.email"
	}
	return &NextcloudProvider{ProviderData: p}
}

// ValidateSession validates the AccessToken
func (p *NextcloudProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
}
