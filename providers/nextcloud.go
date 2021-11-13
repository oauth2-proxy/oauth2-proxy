package providers

import (
	"context"
	"fmt"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
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
	p.ProviderName = nextCloudProviderName
	p.getAuthorizationHeaderFunc = makeOIDCHeader
	if p.EmailClaim == options.OIDCEmailClaim {
		// This implies the email claim has not been overridden, we should set a default
		// for this provider
		p.EmailClaim = "ocs.data.email"
	}
	return &NextcloudProvider{ProviderData: p}
}

// EnrichSession is called after Redeem to allow providers to enrich session fields
// such as User, Email, Groups with provider specific API calls.
func (p *NextcloudProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	json, err := requests.New(p.ValidateURL.String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(s.AccessToken)).
		Do().
		UnmarshalJSON()
	if err != nil {
		return fmt.Errorf("error making request: %v", err)
	}

	email, err := json.GetPath("ocs", "data", "email").String()
	if err != nil {
		return fmt.Errorf("error retrieving email address: %v", err)
	}
	if email != "" {
		s.Email = email
	}

	username, err := json.GetPath("ocs", "data", "id").String()
	if err == nil && username != "" {
		s.User = username
	}

	groups, err := json.GetPath("ocs", "data", "groups").StringArray()
	if err == nil {
		for _, group := range groups {
			if group != "" {
				s.Groups = append(s.Groups, group)
			}
		}
	}

	return nil
}
