package providers

import (
	"context"
	"net/http"
	"net/url"
	"path"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// AtlassianProvider represents an Atlassian-based Identity Provider
type AtlassianProvider struct {
	*ProviderData
	Groups []string
}

var _ Provider = (*AtlassianProvider)(nil)

type me struct {
	AccountsType    string            `json:"account_type"`
	AccountID       string            `json:"account_id"`
	Email           string            `json:"email"`
	Name            string            `json:"name"`
	Picture         string            `json:"picture"`
	AccountStatus   string            `json:"account_status"`
	Nickname        string            `json:"nickname"`
	Locale          string            `json:"locale"`
	ExtendedProfile map[string]string `json:"extended_profile"`
	EmailVerified   bool              `json:"email_verified"`
}

type resource struct {
	ID        string   `json:"id"`
	URL       string   `json:"url"`
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	AvatarURL string   `json:"avatarUrl"`
}

type resources []resource

type group struct {
	Name string `json:"name"`
	Self string `json:"self"`
}

type groups []group

const (
	atlassianProviderName = "Atlassian"
	atlassianDefaultScope = "read:jira-user read:me"
	atlassianPrompt       = "consent"
	atlassianAudience     = "api.atlassian.com"
)

var (
	// Default Login URL for Atlassian.
	// Pre-parsed URL of https://auth.atlassian.com/authorize.
	atlassianDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "auth.atlassian.com",
		Path:   "/authorize",
	}

	// Default Redeem URL for Atlassian.
	// Pre-parsed URL of https://auth.atlassian.com/oauth/access_token.
	atlassianDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "auth.atlassian.com",
		Path:   "/oauth/token",
	}

	// Default Validation URL for Atlassian.
	// ValidationURL is the API Base URL.
	// Other API requests are based on this.
	// Pre-parsed URL of https://api.atlassian.com.
	atlassianDefaultValidateURL = &url.URL{
		Scheme: "https",
		Host:   "api.atlassian.com",
		Path:   "/",
	}
)

// NewAtlassianProvider initiates a new AtlassianProvider
func NewAtlassianProvider(p *ProviderData) *AtlassianProvider {
	p.setProviderDefaults(providerDefaults{
		name:        atlassianProviderName,
		loginURL:    atlassianDefaultLoginURL,
		redeemURL:   atlassianDefaultRedeemURL,
		profileURL:  nil,
		validateURL: atlassianDefaultValidateURL,
		scope:       atlassianDefaultScope,
	})
	p.Prompt = atlassianPrompt
	return &AtlassianProvider{ProviderData: p}
}

func makeAtlassianHeader(accessToken string) http.Header {
	// extra headers required by the Atlassian API when making authenticated requests
	extraHeaders := map[string]string{
		acceptHeader: acceptApplicationJSON,
	}
	return makeAuthorizationHeader(tokenTypeBearer, accessToken, extraHeaders)
}

// SetGroups sets Atlassian Groups
func (p *AtlassianProvider) SetGroups(groups []string) {
	p.Groups = groups
}

// EnrichSessionState updates the Email and User after the initial Redeem
func (p *AtlassianProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	err := p.validateUserGroups(ctx, s)
	if err != nil {
		return err
	}
	return nil
}

// ValidateSessionState validates the AccessToken
func (p *AtlassianProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	return validateToken(ctx, p, s.AccessToken, makeAtlassianHeader(s.AccessToken))
}

// GetLoginURL overrides GetLoginURL to add Atlassian parameters
func (p *AtlassianProvider) GetLoginURL(redirectURI, state string) string {
	extraParams := url.Values{
		"audience": []string{atlassianAudience},
	}
	a := makeLoginURL(p.ProviderData, redirectURI, state, extraParams)
	return a.String()
}

func (p *AtlassianProvider) validateUserGroups(ctx context.Context, s *sessions.SessionState) error {
	me, err := p.getSelfInfo(ctx, s)
	if err != nil {
		logger.Printf("could not get self info, reason: %s", err)
		return err
	}

	resources, err := p.getResources(ctx, s)
	if err != nil {
		logger.Printf("could not get resources, reason: %s", err)
		return err
	}

	isMember := false
	for _, r := range *resources {
		apiURL, err := url.Parse(r.URL)
		if err != nil {
			logger.Printf("could not parse %s, reason: %s", r.URL, err)
			return err
		}

		groups, err := p.getGroups(ctx, s, me, apiURL)
		if err != nil {
			logger.Printf("could not get groups, reason: %s", err)
			return err
		}

		for _, g := range *groups {
			for _, aug := range p.Groups {
				if g.Name == aug {
					isMember = true
				}
			}
		}
	}

	if isMember {
		s.Email = me.Email
		s.User = me.Name
	}

	return nil
}

func (p *AtlassianProvider) getSelfInfo(ctx context.Context, s *sessions.SessionState) (*me, error) {
	var me me

	endpoint := &url.URL{
		Scheme: p.ValidateURL.Scheme,
		Host:   p.ValidateURL.Host,
		Path:   path.Join(p.ValidateURL.Path, "/me"),
	}
	err := requests.New(endpoint.String()).
		WithContext(ctx).
		WithHeaders(makeAtlassianHeader(s.AccessToken)).
		Do().
		UnmarshalInto(&me)
	if err != nil {
		return nil, err
	}

	return &me, nil
}

func (p *AtlassianProvider) getResources(ctx context.Context, s *sessions.SessionState) (*resources, error) {
	var resources resources

	endpoint := &url.URL{
		Scheme: p.ValidateURL.Scheme,
		Host:   p.ValidateURL.Host,
		Path:   path.Join(p.ValidateURL.Path, "/oauth/token/accessible-resources"),
	}
	err := requests.New(endpoint.String()).
		WithContext(ctx).
		WithHeaders(makeAtlassianHeader(s.AccessToken)).
		Do().
		UnmarshalInto(&resources)
	if err != nil {
		return nil, err
	}

	return &resources, nil
}

func (p *AtlassianProvider) getGroups(ctx context.Context, s *sessions.SessionState, me *me, apiURL *url.URL) (*groups, error) {
	var groups groups

	endpoint := &url.URL{
		Scheme: apiURL.Scheme,
		Host:   apiURL.Host,
		Path:   path.Join(apiURL.Path, "/rest/api/3/user/groups"),
	}
	err := requests.New(endpoint.String() + "?accountId=" + me.AccountID).
		WithContext(ctx).
		WithHeaders(makeAtlassianHeader(s.AccessToken)).
		Do().
		UnmarshalInto(&groups)
	if err != nil {
		return nil, err
	}

	return &groups, nil
}
