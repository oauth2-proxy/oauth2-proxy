package providers

import (
	"bytes"
	"context"
	"fmt"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

type SourceHutProvider struct {
	*ProviderData
}

var _ Provider = (*SourceHutProvider)(nil)

const (
	SourceHutProviderName = "SourceHut"
	SourceHutDefaultScope = "meta.sr.ht/PROFILE:RO"
)

var (
	// Default Login URL for SourceHut.
	// Pre-parsed URL of https://meta.sr.ht/oauth2/authorize.
	SourceHutDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "meta.sr.ht",
		Path:   "/oauth2/authorize",
	}

	// Default Redeem URL for SourceHut.
	// Pre-parsed URL of https://meta.sr.ht/oauth2/access-token.
	SourceHutDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "meta.sr.ht",
		Path:   "/oauth2/access-token",
	}

	// Default Profile URL for SourceHut.
	// Pre-parsed URL of https://meta.sr.ht/query.
	SourceHutDefaultProfileURL = &url.URL{
		Scheme: "https",
		Host:   "meta.sr.ht",
		Path:   "/query",
	}

	// Default Validation URL for SourceHut.
	// Pre-parsed URL of https://meta.sr.ht/profile.
	SourceHutDefaultValidateURL = &url.URL{
		Scheme: "https",
		Host:   "meta.sr.ht",
		Path:   "/profile",
	}
)

// NewSourceHutProvider creates a SourceHutProvider using the passed ProviderData
func NewSourceHutProvider(p *ProviderData) *SourceHutProvider {
	p.setProviderDefaults(providerDefaults{
		name:        SourceHutProviderName,
		loginURL:    SourceHutDefaultLoginURL,
		redeemURL:   SourceHutDefaultRedeemURL,
		profileURL:  SourceHutDefaultProfileURL,
		validateURL: SourceHutDefaultValidateURL,
		scope:       SourceHutDefaultScope,
	})

	return &SourceHutProvider{ProviderData: p}
}

// EnrichSession uses the SourceHut userinfo endpoint to populate the session's
// email and username.
func (p *SourceHutProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	json, err := requests.New(p.ProfileURL.String()).
		WithContext(ctx).
		WithMethod("POST").
		SetHeader("Content-Type", "application/json").
		SetHeader("Authorization", "Bearer "+s.AccessToken).
		WithBody(bytes.NewBufferString(`{"query": "{ me { username, email } }"}`)).
		Do().
		UnmarshalSimpleJSON()
	if err != nil {
		logger.Errorf("failed making request %v", err)
		return err
	}

	email, err := json.GetPath("data", "me", "email").String()
	if err != nil {
		return fmt.Errorf("unable to extract email from userinfo endpoint: %v", err)
	}
	s.Email = email

	username, err := json.GetPath("data", "me", "username").String()
	if err != nil {
		return fmt.Errorf("unable to extract username from userinfo endpoint: %v", err)
	}
	s.PreferredUsername = username
	s.User = username

	return nil
}

// ValidateSession validates the AccessToken
func (p *SourceHutProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
}
