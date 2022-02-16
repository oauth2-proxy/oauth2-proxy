package providers

import (
	"context"
	"fmt"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	internaloidc "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/oidc"
	k8serrors "k8s.io/apimachinery/pkg/util/errors"
)

// Provider represents an upstream identity provider implementation
type Provider interface {
	Data() *ProviderData
	GetLoginURL(redirectURI, finalRedirect string, nonce string) string
	Redeem(ctx context.Context, redirectURI, code string) (*sessions.SessionState, error)
	// Deprecated: Migrate to EnrichSession
	GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error)
	EnrichSession(ctx context.Context, s *sessions.SessionState) error
	Authorize(ctx context.Context, s *sessions.SessionState) (bool, error)
	ValidateSession(ctx context.Context, s *sessions.SessionState) bool
	RefreshSession(ctx context.Context, s *sessions.SessionState) (bool, error)
	CreateSessionFromToken(ctx context.Context, token string) (*sessions.SessionState, error)
}

func NewProvider(providerConfig options.Provider) (Provider, error) {
	providerData, err := newProviderDataFromConfig(providerConfig)
	if err != nil {
		return nil, fmt.Errorf("could not create provider data: %v", err)
	}
	switch providerConfig.Type {
	case options.ADFSProvider:
		return NewADFSProvider(providerData, providerConfig.ADFSConfig), nil
	case options.AzureProvider:
		return NewAzureProvider(providerData, providerConfig.AzureConfig), nil
	case options.BitbucketProvider:
		return NewBitbucketProvider(providerData, providerConfig.BitbucketConfig), nil
	case options.DigitalOceanProvider:
		return NewDigitalOceanProvider(providerData), nil
	case options.FacebookProvider:
		return NewFacebookProvider(providerData), nil
	case options.GitHubProvider:
		return NewGitHubProvider(providerData, providerConfig.GitHubConfig), nil
	case options.GitLabProvider:
		return NewGitLabProvider(providerData, providerConfig.GitLabConfig)
	case options.GoogleProvider:
		return NewGoogleProvider(providerData, providerConfig.GoogleConfig)
	case options.KeycloakProvider:
		return NewKeycloakProvider(providerData, providerConfig.KeycloakConfig), nil
	case options.KeycloakOIDCProvider:
		return NewKeycloakOIDCProvider(providerData, providerConfig.KeycloakConfig), nil
	case options.LinkedInProvider:
		return NewLinkedInProvider(providerData), nil
	case options.LoginGovProvider:
		return NewLoginGovProvider(providerData, providerConfig.LoginGovConfig)
	case options.NextCloudProvider:
		return NewNextcloudProvider(providerData), nil
	case options.OIDCProvider:
		return NewOIDCProvider(providerData, providerConfig.OIDCConfig), nil
	default:
		return nil, fmt.Errorf("unknown provider type %q", providerConfig.Type)
	}
}

func newProviderDataFromConfig(providerConfig options.Provider) (*ProviderData, error) {
	p := &ProviderData{
		Scope:            providerConfig.Scope,
		ClientID:         providerConfig.ClientID,
		ClientSecret:     providerConfig.ClientSecret,
		ClientSecretFile: providerConfig.ClientSecretFile,
		Prompt:           providerConfig.Prompt,
		ApprovalPrompt:   providerConfig.ApprovalPrompt,
		AcrValues:        providerConfig.AcrValues,
	}

	needsVerifier, err := providerRequiresOIDCProviderVerifier(providerConfig.Type)
	if err != nil {
		return nil, err
	}

	if needsVerifier {
		pv, err := internaloidc.NewProviderVerifier(context.TODO(), internaloidc.ProviderVerifierOptions{
			AudienceClaims:         providerConfig.OIDCConfig.AudienceClaims,
			ClientID:               providerConfig.ClientID,
			ExtraAudiences:         providerConfig.OIDCConfig.ExtraAudiences,
			IssuerURL:              providerConfig.OIDCConfig.IssuerURL,
			JWKsURL:                providerConfig.OIDCConfig.JwksURL,
			SkipDiscovery:          providerConfig.OIDCConfig.SkipDiscovery,
			SkipIssuerVerification: providerConfig.OIDCConfig.InsecureSkipIssuerVerification,
		})
		if err != nil {
			return nil, fmt.Errorf("error building OIDC ProviderVerifier: %v", err)
		}

		p.Verifier = pv.Verifier()
		if pv.DiscoveryEnabled() {
			// Use the discovered values rather than any specified values
			endpoints := pv.Provider().Endpoints()
			providerConfig.LoginURL = endpoints.AuthURL
			providerConfig.RedeemURL = endpoints.TokenURL
			providerConfig.ProfileURL = endpoints.UserInfoURL
			providerConfig.OIDCConfig.JwksURL = endpoints.JWKsURL
		}
	}

	errs := []error{}
	for name, u := range map[string]struct {
		dst **url.URL
		raw string
	}{
		"login":    {dst: &p.LoginURL, raw: providerConfig.LoginURL},
		"redeem":   {dst: &p.RedeemURL, raw: providerConfig.RedeemURL},
		"profile":  {dst: &p.ProfileURL, raw: providerConfig.ProfileURL},
		"validate": {dst: &p.ValidateURL, raw: providerConfig.ValidateURL},
		"resource": {dst: &p.ProtectedResource, raw: providerConfig.ProtectedResource},
	} {
		var err error
		*u.dst, err = url.Parse(u.raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("could not parse %s URL: %v", name, err))
		}
	}
	if len(errs) > 0 {
		return nil, k8serrors.NewAggregate(errs)
	}

	// Make the OIDC options available to all providers that support it
	p.AllowUnverifiedEmail = providerConfig.OIDCConfig.InsecureAllowUnverifiedEmail
	p.EmailClaim = providerConfig.OIDCConfig.EmailClaim
	p.GroupsClaim = providerConfig.OIDCConfig.GroupsClaim

	// TODO (@NickMeves) - Remove This
	// Backwards Compatibility for Deprecated UserIDClaim option
	if providerConfig.OIDCConfig.EmailClaim == options.OIDCEmailClaim &&
		providerConfig.OIDCConfig.UserIDClaim != options.OIDCEmailClaim {
		p.EmailClaim = providerConfig.OIDCConfig.UserIDClaim
	}

	if p.Scope == "" {
		p.Scope = "openid email profile"

		if len(providerConfig.AllowedGroups) > 0 {
			p.Scope += " groups"
		}
	}
	if providerConfig.OIDCConfig.UserIDClaim == "" {
		providerConfig.OIDCConfig.UserIDClaim = "email"
	}

	p.setAllowedGroups(providerConfig.AllowedGroups)

	return p, nil
}

func providerRequiresOIDCProviderVerifier(providerType options.ProviderType) (bool, error) {
	switch providerType {
	case options.BitbucketProvider, options.DigitalOceanProvider, options.FacebookProvider, options.GitHubProvider,
		options.GoogleProvider, options.KeycloakProvider, options.LinkedInProvider, options.LoginGovProvider, options.NextCloudProvider:
		return false, nil
	case options.ADFSProvider, options.AzureProvider, options.GitLabProvider, options.KeycloakOIDCProvider, options.OIDCProvider:
		return true, nil
	default:
		return false, fmt.Errorf("unknown provider type: %s", providerType)
	}
}
