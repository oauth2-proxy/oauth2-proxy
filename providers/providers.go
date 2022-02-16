package providers

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	internaloidc "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/oidc"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
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
		oidcProvider, verifier, err := newOIDCProviderVerifier(providerConfig)
		if err != nil {
			return nil, fmt.Errorf("error setting OIDC configuration: %v", err)
		}

		p.Verifier = verifier
		if oidcProvider != nil {
			// Use the discovered values rather than any specified values
			providerConfig.LoginURL = oidcProvider.Endpoint().AuthURL
			providerConfig.RedeemURL = oidcProvider.Endpoint().TokenURL
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

func newOIDCProviderVerifier(providerConfig options.Provider) (*oidc.Provider, internaloidc.IDTokenVerifier, error) {
	// If the issuer isn't set, default it for platforms where it makes sense
	if providerConfig.OIDCConfig.IssuerURL == "" {
		switch providerConfig.Type {
		case "gitlab":
			providerConfig.OIDCConfig.IssuerURL = "https://gitlab.com"
		case "oidc":
			return nil, nil, errors.New("missing required setting: OIDC Issuer URL cannot be empty")
		}
	}

	switch {
	case providerConfig.OIDCConfig.InsecureSkipIssuerVerification && !providerConfig.OIDCConfig.SkipDiscovery:
		verifier, err := newInsecureSkipIssuerVerificationOIDCVerifier(providerConfig)
		return nil, verifier, err
	case providerConfig.OIDCConfig.SkipDiscovery:
		verifier, err := newSkipDiscoveryOIDCVerifier(providerConfig)
		return nil, verifier, err
	default:
		return newDiscoveryOIDCProviderVerifier(providerConfig)
	}
}

func newDiscoveryOIDCProviderVerifier(providerConfig options.Provider) (*oidc.Provider, internaloidc.IDTokenVerifier, error) {
	// Configure discoverable provider data.
	provider, err := oidc.NewProvider(context.TODO(), providerConfig.OIDCConfig.IssuerURL)
	if err != nil {
		return nil, nil, err
	}
	verificationOptions := internaloidc.IDTokenVerificationOptions{
		AudienceClaims: providerConfig.OIDCConfig.AudienceClaims,
		ClientID:       providerConfig.ClientID,
		ExtraAudiences: providerConfig.OIDCConfig.ExtraAudiences,
	}
	verifier := internaloidc.NewVerifier(provider.Verifier(&oidc.Config{
		ClientID:          providerConfig.ClientID,
		SkipIssuerCheck:   providerConfig.OIDCConfig.InsecureSkipIssuerVerification,
		SkipClientIDCheck: true, // client id check is done within oauth2-proxy: IDTokenVerifier.Verify
	}), verificationOptions)

	return provider, verifier, nil
}

func newInsecureSkipIssuerVerificationOIDCVerifier(providerConfig options.Provider) (internaloidc.IDTokenVerifier, error) {
	// go-oidc doesn't let us pass bypass the issuer check this in the oidc.NewProvider call
	// (which uses discovery to get the URLs), so we'll do a quick check ourselves and if
	// we get the URLs, we'll just use the non-discovery path.

	logger.Printf("Performing OIDC Discovery...")

	requestURL := strings.TrimSuffix(providerConfig.OIDCConfig.IssuerURL, "/") + "/.well-known/openid-configuration"
	body, err := requests.New(requestURL).
		Do().
		UnmarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to discover OIDC configuration: %v", err)
	}

	// Prefer manually configured URLs. It's a bit unclear
	// why you'd be doing discovery and also providing the URLs
	// explicitly though...
	if providerConfig.LoginURL == "" {
		providerConfig.LoginURL = body.Get("authorization_endpoint").MustString()
	}

	if providerConfig.RedeemURL == "" {
		providerConfig.RedeemURL = body.Get("token_endpoint").MustString()
	}

	if providerConfig.OIDCConfig.JwksURL == "" {
		providerConfig.OIDCConfig.JwksURL = body.Get("jwks_uri").MustString()
	}

	if providerConfig.ProfileURL == "" {
		providerConfig.ProfileURL = body.Get("userinfo_endpoint").MustString()
	}

	// Now we have performed the discovery, construct the verifier manually
	return newSkipDiscoveryOIDCVerifier(providerConfig)
}

func newSkipDiscoveryOIDCVerifier(providerConfig options.Provider) (internaloidc.IDTokenVerifier, error) {
	var errs []error

	// Construct a manual IDTokenVerifier from issuer URL & JWKS URI
	// instead of metadata discovery if we enable -skip-oidc-discovery.
	// In this case we need to make sure the required endpoints for
	// the provider are configured.
	if providerConfig.LoginURL == "" {
		errs = append(errs, errors.New("missing required setting: login-url"))
	}
	if providerConfig.RedeemURL == "" {
		errs = append(errs, errors.New("missing required setting: redeem-url"))
	}
	if providerConfig.OIDCConfig.JwksURL == "" {
		errs = append(errs, errors.New("missing required setting: oidc-jwks-url"))
	}
	if len(errs) > 0 {
		return nil, k8serrors.NewAggregate(errs)
	}

	keySet := oidc.NewRemoteKeySet(context.TODO(), providerConfig.OIDCConfig.JwksURL)
	verificationOptions := internaloidc.IDTokenVerificationOptions{
		AudienceClaims: providerConfig.OIDCConfig.AudienceClaims,
		ClientID:       providerConfig.ClientID,
		ExtraAudiences: providerConfig.OIDCConfig.ExtraAudiences,
	}
	verifier := internaloidc.NewVerifier(oidc.NewVerifier(providerConfig.OIDCConfig.IssuerURL, keySet, &oidc.Config{
		ClientID:          providerConfig.ClientID,
		SkipIssuerCheck:   providerConfig.OIDCConfig.InsecureSkipIssuerVerification,
		SkipClientIDCheck: true, // client id check is done within oauth2-proxy: IDTokenVerifier.Verify
	}), verificationOptions)
	return verifier, nil
}
