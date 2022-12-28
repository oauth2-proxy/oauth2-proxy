package providers

import (
	"context"
	"errors"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// MastodonProvider represents a Mastodon based Identity Provider
type MastodonProvider struct {
	*ProviderData
}

var _ Provider = (*MastodonProvider)(nil)

const (
	mastodonProviderName = "Mastodon"
	mastodonDefaultScope = "read:accounts"
)

// NewMastodonProvider initiates a new MastodonProvider
func NewMastodonProvider(p *ProviderData, opts options.MastodonOptions) (*MastodonProvider, error) {
	mastodonURL, err := url.Parse(opts.URL)
	if err != nil {
		return nil, err
	}

	loginURL := mastodonURL.JoinPath("oauth/authorize")
	redeemURL := mastodonURL.JoinPath("oauth/token")
	verifyCredsURL := mastodonURL.JoinPath("api/v1/accounts/verify_credentials")

	p.setProviderDefaults(providerDefaults{
		name:        mastodonProviderName,
		loginURL:    loginURL,
		redeemURL:   redeemURL,
		profileURL:  verifyCredsURL,
		validateURL: verifyCredsURL,
		scope:       mastodonDefaultScope,
	})
	p.getAuthorizationHeaderFunc = makeOIDCHeader

	return &MastodonProvider{ProviderData: p}, nil
}

// GetEmailAddress returns the Mastodon account name.
// For users local to this instance, this will not include a domain name.
func (p *MastodonProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {
	if s.AccessToken == "" {
		return "", errors.New("missing access token")
	}

	json, err := requests.New(p.ProfileURL.String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(s.AccessToken)).
		Do().
		UnmarshalSimpleJSON()
	if err != nil {
		return "", err
	}

	email, err := json.GetPath("acct").String()
	if err != nil {
		return "", err
	}
	return email, nil
}

// ValidateSession validates the AccessToken
func (p *MastodonProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
}
