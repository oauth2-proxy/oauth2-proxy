package providers

import (
	"context"
	"net/url"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

// BitbucketProvider represents an Bitbucket based Identity Provider
type BitbucketProvider struct {
	*ProviderData
	Team       string
	Repository string
}

var _ Provider = (*BitbucketProvider)(nil)

const (
	bitbucketProviderName = "Bitbucket"
	bitbucketDefaultScope = "email"
)

var (
	// Default Login URL for Bitbucket.
	// Pre-parsed URL of https://bitbucket.org/site/oauth2/authorize.
	bitbucketDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "bitbucket.org",
		Path:   "/site/oauth2/authorize",
	}

	// Default Redeem URL for Bitbucket.
	// Pre-parsed URL of https://bitbucket.org/site/oauth2/access_token.
	bitbucketDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "bitbucket.org",
		Path:   "/site/oauth2/access_token",
	}

	// Default Validation URL for Bitbucket.
	// This simply returns the email of the authenticated user.
	// Bitbucket does not have a Profile URL to use.
	// Pre-parsed URL of https://api.bitbucket.org/2.0/user/emails.
	bitbucketDefaultValidateURL = &url.URL{
		Scheme: "https",
		Host:   "api.bitbucket.org",
		Path:   "/2.0/user/emails",
	}
)

// NewBitbucketProvider initiates a new BitbucketProvider
func NewBitbucketProvider(p *ProviderData, opts options.BitbucketOptions) *BitbucketProvider {
	p.setProviderDefaults(providerDefaults{
		name:        bitbucketProviderName,
		loginURL:    bitbucketDefaultLoginURL,
		redeemURL:   bitbucketDefaultRedeemURL,
		profileURL:  nil,
		validateURL: bitbucketDefaultValidateURL,
		scope:       bitbucketDefaultScope,
	})

	provider := &BitbucketProvider{ProviderData: p}

	if opts.Team != "" {
		provider.setTeam(opts.Team)
	}
	if opts.Repository != "" {
		provider.setRepository(opts.Repository)
	}
	return provider
}

// setTeam defines the Bitbucket team the user must be part of
func (p *BitbucketProvider) setTeam(team string) {
	p.Team = team
	if !strings.Contains(p.Scope, "team") {
		p.Scope += " team"
	}
}

// setRepository defines the repository the user must have access to
func (p *BitbucketProvider) setRepository(repository string) {
	p.Repository = repository
	if !strings.Contains(p.Scope, "repository") {
		p.Scope += " repository"
	}
}

// GetEmailAddress returns the email of the authenticated user
func (p *BitbucketProvider) GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error) {

	var emails struct {
		Values []struct {
			Email   string `json:"email"`
			Primary bool   `json:"is_primary"`
		}
	}
	var teams struct {
		Values []struct {
			Name string `json:"username"`
		}
	}
	var repositories struct {
		Values []struct {
			FullName string `json:"full_name"`
		}
	}

	requestURL := p.ValidateURL.String() + "?access_token=" + s.AccessToken
	err := requests.New(requestURL).
		WithContext(ctx).
		WithClient(p.Client).
		Do().
		UnmarshalInto(&emails)
	if err != nil {
		logger.Errorf("failed making request: %v", err)
		return "", err
	}

	if p.Team != "" {
		teamURL := &url.URL{}
		*teamURL = *p.ValidateURL
		teamURL.Path = "/2.0/teams"

		requestURL := teamURL.String() + "?role=member&access_token=" + s.AccessToken

		err := requests.New(requestURL).
			WithContext(ctx).
			WithClient(p.Client).
			Do().
			UnmarshalInto(&teams)
		if err != nil {
			logger.Errorf("failed requesting teams membership: %v", err)
			return "", err
		}
		var found = false
		for _, team := range teams.Values {
			if p.Team == team.Name {
				found = true
				break
			}
		}
		if !found {
			logger.Error("team membership test failed, access denied")
			return "", nil
		}
	}

	if p.Repository != "" {
		repositoriesURL := &url.URL{}
		*repositoriesURL = *p.ValidateURL
		repositoriesURL.Path = "/2.0/repositories/" + strings.Split(p.Repository, "/")[0]

		requestURL := repositoriesURL.String() + "?role=contributor" +
			"&q=full_name=" + url.QueryEscape("\""+p.Repository+"\"") +
			"&access_token=" + s.AccessToken

		err := requests.New(requestURL).
			WithContext(ctx).
			WithClient(p.Client).
			Do().
			UnmarshalInto(&repositories)
		if err != nil {
			logger.Errorf("failed checking repository access: %v", err)
			return "", err
		}

		var found = false
		for _, repository := range repositories.Values {
			if p.Repository == repository.FullName {
				found = true
				break
			}
		}
		if !found {
			logger.Error("repository access test failed, access denied")
			return "", nil
		}
	}

	for _, email := range emails.Values {
		if email.Primary {
			return email.Email, nil
		}
	}

	return "", nil
}
