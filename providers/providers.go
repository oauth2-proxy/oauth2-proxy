package providers

import (
	"github.com/bitly/go-simplejson"
)

type Provider interface {
	Data() *ProviderData
	GetEmailAddress(auth_response *simplejson.Json,
		access_token string) (string, error)
	ValidateToken(access_token string) bool
}

func New(provider string, p *ProviderData) Provider {
	switch provider {
	case "myusa":
		return NewMyUsaProvider(p)
	case "linkedin":
		return NewLinkedInProvider(p)
	default:
		return NewGoogleProvider(p)
	}
}
