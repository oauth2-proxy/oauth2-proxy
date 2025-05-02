package providers

import (
	"context"
	"fmt"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// DiscordProvider represents a Discord based Identity Provider
type DiscordProvider struct {
	*ProviderData
	restrictedUserIDs map[string]bool
}

var _ Provider = (*DiscordProvider)(nil)

const (
	discordProviderName = "Discord"
	discordDefaultScope = "identify"
)

var (
	// Default Login URL for Discord.
	// Pre-parsed URL of https://discord.com/api/oauth2/authorize.
	discordDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "discord.com",
		Path:   "/api/oauth2/authorize",
	}

	// Default Redeem URL for Discord.
	// Pre-parsed URL of https://discord.com/api/oauth2/token
	discordDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "discord.com",
		Path:   "/api/oauth2/token",
	}

	// Profile URL for Discord.
	// Pre-parsed URL of https://discord.com/api/oauth2/@me
	discordDefaultProfileURL = &url.URL{
		Scheme: "https",
		Host:   "discord.com",
		Path:   "/api/oauth2/@me",
	}
)

// NewDiscordProvider initiates a new DiscordProvider
func NewDiscordProvider(p *ProviderData, opts options.DiscordOptions) *DiscordProvider {
	p.setProviderDefaults(providerDefaults{
		name:        discordProviderName,
		loginURL:    discordDefaultLoginURL,
		redeemURL:   discordDefaultRedeemURL,
		profileURL:  discordDefaultProfileURL,
		validateURL: discordDefaultProfileURL,
		scope:       discordDefaultScope,
	})
	restrictedUserIDs := make(map[string]bool, len(opts.RestrictedUserIDs))
	for _, userID := range opts.RestrictedUserIDs {
		restrictedUserIDs[userID] = true
	}
	return &DiscordProvider{
		ProviderData:      p,
		restrictedUserIDs: restrictedUserIDs,
	}
}

func (p *DiscordProvider) Authorize(ctx context.Context, s *sessions.SessionState) (bool, error) {
	if ok, err := p.ProviderData.Authorize(ctx, s); err != nil {
		// error while validating authorization
		return false, err
	} else if !ok {
		// not authorized
		return false, nil
	}
	return p.validateUserID(s), nil
}

func (p *DiscordProvider) validateUserID(s *sessions.SessionState) bool {
	// check custom parameters
	if len(p.restrictedUserIDs) == 0 {
		// no restrictedUserIDs parametered, user is allowed to access
		return true
	}
	return p.restrictedUserIDs[s.User]
}

// ValidateSession validates the AccessToken.
// Discord requires 'Accept' header to be set to 'application/json'
func (p *DiscordProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
}

// EnrichSession enriches the session with user information
func (p *DiscordProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	token, err := p.getTokenInfo(ctx, s)
	if err != nil {
		return err
	}
	s.User = token.User.ID
	s.PreferredUsername = token.User.Username
	return nil
}

type discordTokenInfo struct {
	User struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	} `json:"user"`
}

// Retrieve current token Info
// https://discord.com/developers/docs/topics/oauth2#get-current-authorization-information
func (p *DiscordProvider) getTokenInfo(ctx context.Context, s *sessions.SessionState) (*discordTokenInfo, error) {
	var tokenInfo discordTokenInfo
	err := requests.New(discordDefaultProfileURL.String()).
		WithContext(ctx).
		SetHeader("Authorization", "Bearer "+s.AccessToken).
		Do().
		UnmarshalInto(&tokenInfo)
	if err != nil {
		return nil, fmt.Errorf("error getting token info: %w", err)
	}

	return &tokenInfo, nil
}
