package providers

import (
	"errors"
	"github.com/bitly/oauth2_proxy/cookie"
)

type Provider interface {
	Data() *ProviderData
	GetEmailAddress(*SessionState) (string, error)
	GetGroups(*SessionState, string) (string, error)
	Redeem(string, string) (*SessionState, error)
	ValidateGroup(*SessionState) bool
	ValidateSessionState(*SessionState) bool
	GetLoginURL(redirectURI, finalRedirect string) string
	RefreshSessionIfNeeded(*SessionState) (bool, error)
	SessionFromCookie(string, *cookie.Cipher) (*SessionState, error)
	CookieForSession(*SessionState, *cookie.Cipher) (string, error)
}

func New(provider string, p *ProviderData) (Provider, error) {
	switch provider {
	case "myusa":
		return NewMyUsaProvider(p), nil
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
	case "google":
		return NewGoogleProvider(p), nil
	default:
		return nil, errors.New("missing setting: provider")
	}
}
