package providers

import (
	"net/url"
)

// GitHubProvider represents an GitHub based Identity Provider
type GitHubProvider struct {
	*ProviderData
}

var _ Provider = (*GitHubProvider)(nil)

const (
	githubProviderName = "GitHub"
	githubDefaultScope = "user:email read:org"
	orgTeamSeparator   = ":"
)

var (
	// Default Login URL for GitHub.
	// Pre-parsed URL of https://github.org/login/oauth/authorize.
	githubDefaultLoginURL = &url.URL{
		Scheme: "https",
		Host:   "github.com",
		Path:   "/login/oauth/authorize",
	}

	// Default Redeem URL for GitHub.
	// Pre-parsed URL of https://github.org/login/oauth/access_token.
	githubDefaultRedeemURL = &url.URL{
		Scheme: "https",
		Host:   "github.com",
		Path:   "/login/oauth/access_token",
	}

	// Default Validation URL for GitHub.
	// ValidationURL is the API Base URL.
	// Other API requests are based off of this (eg to fetch users/groups).
	// Pre-parsed URL of https://api.github.com/.
	githubDefaultValidateURL = &url.URL{
		Scheme: "https",
		Host:   "api.github.com",
		Path:   "/",
	}
)

// NewGitHubProvider initiates a new GitHubProvider
func NewGitHubProvider(p *ProviderData) *GitHubProvider {
	p.setProviderDefaults(providerDefaults{
		name:        githubProviderName,
		loginURL:    githubDefaultLoginURL,
		redeemURL:   githubDefaultRedeemURL,
		profileURL:  nil,
		validateURL: githubDefaultValidateURL,
		scope:       githubDefaultScope,
	})

	provider := &GitHubProvider{ProviderData: p}
	return provider
}

// func makeGitHubHeader(accessToken string) http.Header {
// 	// extra headers required by the GitHub API when making authenticated requests
// 	extraHeaders := map[string]string{
// 		acceptHeader: "application/vnd.github.v3+json",
// 	}
// 	return makeAuthorizationHeader(tokenTypeToken, accessToken, extraHeaders)
// }

// ValidateSession validates the AccessToken
// func (p *GitHubProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
// 	return validateToken(ctx, p, s.AccessToken, makeGitHubHeader(s.AccessToken))
// }
