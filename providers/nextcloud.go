package providers

import "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"

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
