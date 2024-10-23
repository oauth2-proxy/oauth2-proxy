package providers

import (
	"context"
	"fmt"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// DiscordProvider represents an Discord based Identity Provider
type DiscordProvider struct {
	*ProviderData
}

var _ Provider = (*DiscordProvider)(nil)

const (
	discordProviderName = "Discord"
	discordDefaultScope = "identify email guilds"
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

	// Default Validate URL for Discord.
	// Pre-parsed URL of https://discord.com/api/users/@me
	discordDefaultValidateURL = &url.URL{
		Scheme: "https",
		Host:   "discord.com",
		Path:   "/api/users/@me",
	}

	// Default Validate URL for Discord.
	// Pre-parsed URL of https://discord.com/api/users/@me/guilds
	discordGuildURL = &url.URL{
		Scheme: "https",
		Host:   "discord.com",
		Path:   "/api/users/@me/guilds",
	}
)

// NewDiscordProvider initiates a new DiscordProvider
func NewDiscordProvider(p *ProviderData, opts options.DiscordOptions) *DiscordProvider {
	p.setProviderDefaults(providerDefaults{
		name:        discordProviderName,
		loginURL:    discordDefaultLoginURL,
		redeemURL:   discordDefaultRedeemURL,
		profileURL:  discordDefaultValidateURL,
		validateURL: discordDefaultValidateURL,
		scope:       discordDefaultScope,
	})
	p.setAllowedGroups(opts.Guilds)
	return &DiscordProvider{ProviderData: p}
}

func (p *DiscordProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	user, err := p.getUserInfo(ctx, s)
	if err != nil {
		return err
	}

	s.User = fmt.Sprintf("%s#%s", user.Username, user.Discriminator)
	s.PreferredUsername = user.Username
	s.Email = user.Email

	guilds, err := p.getUserGuilds(ctx, s)
	if err != nil {
		return err
	}

	for _, guild := range guilds {
		s.Groups = append(s.Groups, guild.ID)
	}

	return nil
}

// https://discord.com/developers/docs/resources/user#user-object
type discordUserInfo struct {
	ID            string `json:"id"`
	Username      string `json:"username"`
	Email         string `json:"email"`
	Verified      bool   `json:"verified"`
	Discriminator string `json:"discriminator"`
	// Avatar   string `json:"avatar"`
	// Flags    int    `json:"flags"`
}

// Retrive user Info
// https://discord.com/developers/docs/resources/user#get-user
func (p *DiscordProvider) getUserInfo(ctx context.Context, s *sessions.SessionState) (*discordUserInfo, error) {
	var userinfo discordUserInfo
	err := requests.New(discordDefaultValidateURL.String()).
		WithContext(ctx).
		SetHeader("Authorization", "Bearer "+s.AccessToken).
		Do().
		UnmarshalInto(&userinfo)
	if err != nil {
		return nil, fmt.Errorf("error getting user's guilds info: %v", err)
	}

	return &userinfo, nil
}

// https://discord.com/developers/docs/resources/guild#guild-object
type discordGuild struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Retrieve user guilds
// https://discord.com/developers/docs/resources/user#get-current-user-guilds
func (p *DiscordProvider) getUserGuilds(ctx context.Context, s *sessions.SessionState) ([]discordGuild, error) {
	guilds := []discordGuild{}
	err := requests.New(discordGuildURL.String()).
		WithContext(ctx).
		SetHeader("Authorization", "Bearer "+s.AccessToken).
		Do().
		UnmarshalInto(&guilds)
	if err != nil {
		return nil, fmt.Errorf("error getting user's guilds info: %v", err)
	}

	return guilds, nil
}

// ValidateSession validates the AccessToken
func (p *DiscordProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeOIDCHeader(s.AccessToken))
}
