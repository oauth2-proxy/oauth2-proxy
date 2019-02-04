package providers

import (
	"github.com/bitly/oauth2_proxy/cookie"
)

type Provider interface {
	Data() *ProviderData
	GetUserDetails(*SessionState) (map[string]string, error)
	GetUserName(*SessionState) (string, error)
	GetGroups(*SessionState, string) (map[string]string, error)
	Redeem(string, string) (*SessionState, error)
	ValidateGroup(*SessionState) bool
	ValidateExemptions(*SessionState) (bool, string)
	ValidateSessionState(*SessionState) bool
	GetLoginURL(redirectURI, finalRedirect string) string
	RefreshSessionIfNeeded(*SessionState) (bool, error)
	SessionFromCookie(string, *cookie.Cipher) (*SessionState, error)
	CookieForSession(*SessionState, *cookie.Cipher) (string, error)
}

func New(provider string, p *ProviderData) (Provider, error) {
	switch provider {
	case "linkedin":
		return NewLinkedInProvider(p), nil
	case "facebook":
		return NewFacebookProvider(p), nil
	case "github":
		return NewGitHubProvider(p), nil
	case "azure":
		return NewAzureProvider(p), nil
	case "gitlab":
		return NewGitLabProvider(p), nil
	case "oidc":
		return NewOIDCProvider(p), nil
	default:
		return NewGoogleProvider(p), nil
	}
}
