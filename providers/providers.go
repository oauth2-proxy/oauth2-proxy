package providers

import (
	"context"

	oidc "github.com/coreos/go-oidc"
	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/encryption"
	"golang.org/x/oauth2"
)

// Provider represents an upstream identity provider implementation
type Provider interface {
	Data() *ProviderData
	GetEmailAddress(*sessions.SessionState) (string, error)
	GetUserName(*sessions.SessionState) (string, error)
	Redeem(string, string) (*sessions.SessionState, error)
	ValidateGroup(string) bool
	ValidateSessionState(*sessions.SessionState) bool
	GetLoginURL(redirectURI, finalRedirect string) string
	RefreshSessionIfNeeded(*sessions.SessionState) (bool, error)
	SessionFromCookie(string, *encryption.Cipher) (*sessions.SessionState, error)
	CookieForSession(*sessions.SessionState, *encryption.Cipher) (string, error)
}

// Redeemer interface allows injecting custom methods for Redeem
type Redeemer interface {
	getAuthFlowConfig() *oauth2.Config
	getAuthFlowConfigWithRedirect(string) *oauth2.Config
	exchangeCodeForToken(context.Context, *oauth2.Config, string) (*oauth2.Token, error)
	exchangeRefreshTokenForToken(context.Context, *oauth2.Config, string) (*oauth2.Token, error)
	verifyIDToken(context.Context, *oauth2.Token) (*oidc.IDToken, error)
	createSessionState(*oidc.IDToken, *oauth2.Token) (*sessions.SessionState, error)
}

// ClaimExporter abstracts different claims that providers accepts
type ClaimExporter interface {
	getTemplate() interface{}
	normalize(interface{}) *GenericClaims
}

// UserInfoFiller allow defining custom way of getting user and email
type UserInfoFiller interface {
	fillEmail(*oauth2.Token) (string, error)
	fillUser(*GenericClaims, *oauth2.Token) string
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
	case "keycloak":
		return NewKeycloakProvider(p)
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
