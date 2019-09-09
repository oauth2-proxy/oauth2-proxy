package providers

import (
	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/encryption"
)

// Provider represents an upstream identity provider implementation
type Provider interface {
	Data() *ProviderData
	GetUserDetails(*sessions.SessionState) (*UserDetails, error)
	GetUserName(*sessions.SessionState) (string, error)
	GetGroups(*sessions.SessionState, string) (map[string]string, error)
	Redeem(string, string) (*sessions.SessionState, error)
	ValidateGroup(string) bool
	ValidateGroupWithSession(*sessions.SessionState) bool
	ValidateExemptions(*sessions.SessionState) (bool, string)
	ValidateSessionState(*sessions.SessionState) bool
	GetLoginURL(redirectURI, finalRedirect string) string
	RefreshSessionIfNeeded(*sessions.SessionState) (bool, error)
	SessionFromCookie(string, *encryption.Cipher) (*sessions.SessionState, error)
	CookieForSession(*sessions.SessionState, *encryption.Cipher) (string, error)
}

type UserDetails struct {
	Email string
	UID   string
}

// New provides a new Provider based on the configured provider string
func New(provider string, p *ProviderData) Provider {
	switch provider {
	case "linkedin":
		return NewLinkedInProvider(p)
	case "facebook":
		return NewFacebookProvider(p)
	case "github":
		return NewGitHubProvider(p)
	case "azure":
		return NewAzureProvider(p)
	case "gitlab":
		return NewGitLabProvider(p)
	case "oidc":
		return NewOIDCProvider(p)
	case "login.gov":
		return NewLoginGovProvider(p)
	case "bitbucket":
		return NewBitbucketProvider(p)
	default:
		return NewGoogleProvider(p)
	}
}
