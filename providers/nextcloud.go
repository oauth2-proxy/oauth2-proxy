package providers

import (
	"context"
	"fmt"

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
		return fmt.Errorf("error requesting ocs data: %v", err)
	}

	data := json.Get("ocs").Get("data")

	id, err := data.Get("id").String()
	if err != nil {
		return err
	}
	s.User = id

	email, err := data.Get("email").String()
	if err != nil {
		return err
	}
	s.Email = email

	groups, err := data.Get("groups").StringArray()
	if err != nil {
		return err
	}
	s.Groups = groups

	return nil
}
