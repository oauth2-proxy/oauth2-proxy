package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Jing-ze/oauth2-proxy/pkg/apis/options"
	"github.com/Jing-ze/oauth2-proxy/pkg/apis/sessions"
	internaloidc "github.com/Jing-ze/oauth2-proxy/pkg/providers/oidc"
	"github.com/Jing-ze/oauth2-proxy/pkg/providers/util"
	pkgutil "github.com/Jing-ze/oauth2-proxy/pkg/util"

	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
)

const (
	CodeChallengeMethodPlain = "plain"
	CodeChallengeMethodS256  = "S256"
)

// Provider represents an upstream identity provider implementation
type Provider interface {
	Data() *ProviderData
	GetLoginURL(redirectURI, finalRedirect, nonce string, extraParams url.Values) string
	Redeem(ctx context.Context, redirectURI, code, codeVerifier string, client wrapper.HttpClient, callback func(args ...interface{}), timeout uint32) error
	// Deprecated: Migrate to EnrichSession
	GetEmailAddress(ctx context.Context, s *sessions.SessionState) (string, error)
	EnrichSession(ctx context.Context, s *sessions.SessionState) error
	Authorize(ctx context.Context, s *sessions.SessionState) (bool, error)
	ValidateSession(ctx context.Context, s *sessions.SessionState) bool
	RefreshSession(ctx context.Context, s *sessions.SessionState, client wrapper.HttpClient, callback func(args ...interface{}), timeout uint32) (bool, error)
}

func NewProvider(providerConfig options.Provider) (Provider, error) {
	providerData, err := newProviderDataFromConfig(providerConfig)
	if err != nil {
		return nil, fmt.Errorf("could not create provider data: %v", err)
	}
	switch providerConfig.Type {
	case options.OIDCProvider:
		return NewOIDCProvider(providerData, providerConfig.OIDCConfig), nil
	default:
		return nil, fmt.Errorf("unknown provider type %q", providerConfig.Type)
	}
}

func NewVerifierFromConfig(providerConfig options.Provider, p *ProviderData, client wrapper.HttpClient) error {

	needsVerifier, err := providerRequiresOIDCProviderVerifier(providerConfig.Type)
	if err != nil {
		return err
	}
	if needsVerifier {
		verifierOptions := internaloidc.ProviderVerifierOptions{
			AudienceClaims:         providerConfig.OIDCConfig.AudienceClaims,
			ClientID:               providerConfig.ClientID,
			ExtraAudiences:         providerConfig.OIDCConfig.ExtraAudiences,
			IssuerURL:              providerConfig.OIDCConfig.IssuerURL,
			JWKsURL:                providerConfig.OIDCConfig.JwksURL,
			SkipDiscovery:          providerConfig.OIDCConfig.SkipDiscovery,
			SkipIssuerVerification: providerConfig.OIDCConfig.InsecureSkipIssuerVerification,
		}

		var providerJson internaloidc.ProviderJSON
		requestURL := strings.TrimSuffix(verifierOptions.IssuerURL, "/") + "/.well-known/openid-configuration"
		client.Get(requestURL, nil, func(statusCode int, responseHeaders http.Header, responseBody []byte) {
			if statusCode != http.StatusOK {
				pkgutil.Logger.Errorf("openid-configuration http call failed, status: %d", statusCode)
				return
			}
			json.Unmarshal(responseBody, &providerJson)
			pv, _ := internaloidc.NewProviderVerifier(context.TODO(), verifierOptions, providerJson)
			p.Verifier = pv.Verifier()
			if pv.DiscoveryEnabled() {
				// Use the discovered values rather than any specified values
				endpoints := pv.Provider().Endpoints()
				pkce := pv.Provider().PKCE()
				providerConfig.LoginURL = endpoints.AuthURL
				providerConfig.RedeemURL = endpoints.TokenURL
				providerConfig.ProfileURL = endpoints.UserInfoURL
				providerConfig.OIDCConfig.JwksURL = endpoints.JWKsURL
				p.SupportedCodeChallengeMethods = pkce.CodeChallengeAlgs
			}
			providerConfigInfoCheck(providerConfig, p)
			(*p.Verifier.GetKeySet()).UpdateKeys(client, providerConfig.OIDCConfig.VerifierRequestTimeout, func(args ...interface{}) {})
			p.StoredSession.RemoteKeySet = p.Verifier.GetKeySet()
		}, providerConfig.OIDCConfig.VerifierRequestTimeout)
		return nil
	}
	errs := providerConfigInfoCheck(providerConfig, p)
	return util.NewAggregate(errs)
}

func newProviderDataFromConfig(providerConfig options.Provider) (*ProviderData, error) {
	p := &ProviderData{
		Scope:           providerConfig.Scope,
		ClientID:        providerConfig.ClientID,
		ClientSecret:    providerConfig.ClientSecret,
		RedeemTimeout:   providerConfig.RedeemTimeout,
		VerifierTimeout: providerConfig.OIDCConfig.VerifierRequestTimeout,
	}

	errs := providerConfigInfoCheck(providerConfig, p)
	// handle LoginURLParameters
	errs = append(errs, p.compileLoginParams(providerConfig.LoginURLParameters)...)

	if len(errs) > 0 {
		return nil, util.NewAggregate(errs)
	}

	// Make the OIDC options available to all providers that support it
	p.EmailClaim = providerConfig.OIDCConfig.EmailClaim
	p.GroupsClaim = providerConfig.OIDCConfig.GroupsClaim
	p.SkipClaimsFromProfileURL = providerConfig.SkipClaimsFromProfileURL

	// Set PKCE enabled or disabled based on discovery and force options
	p.CodeChallengeMethod = parseCodeChallengeMethod(providerConfig)
	if len(p.SupportedCodeChallengeMethods) != 0 && p.CodeChallengeMethod == "" {
		pkgutil.Logger.Infof("Warning: Your provider supports PKCE methods %+q, but you have not enabled one with --code-challenge-method", p.SupportedCodeChallengeMethods)
	}

	if providerConfig.OIDCConfig.UserIDClaim == "" {
		providerConfig.OIDCConfig.UserIDClaim = "email"
	}

	// TODO (@NickMeves) - Remove This
	// Backwards Compatibility for Deprecated UserIDClaim option
	if providerConfig.OIDCConfig.EmailClaim == options.OIDCEmailClaim &&
		providerConfig.OIDCConfig.UserIDClaim != options.OIDCEmailClaim {
		p.EmailClaim = providerConfig.OIDCConfig.UserIDClaim
	}

	p.setAllowedGroups(providerConfig.AllowedGroups)

	return p, nil
}

// Pick the most appropriate code challenge method for PKCE
// At this time we do not consider what the server supports to be safe and
// only enable PKCE if the user opts-in
func parseCodeChallengeMethod(providerConfig options.Provider) string {
	switch {
	case providerConfig.CodeChallengeMethod != "":
		return providerConfig.CodeChallengeMethod
	default:
		return ""
	}
}

func providerRequiresOIDCProviderVerifier(providerType options.ProviderType) (bool, error) {
	switch providerType {
	case options.OIDCProvider:
		return true, nil
	default:
		return false, fmt.Errorf("unknown provider type: %s", providerType)
	}
}

func providerConfigInfoCheck(providerConfig options.Provider, p *ProviderData) []error {
	errs := []error{}
	for name, u := range map[string]struct {
		dst **url.URL
		raw string
	}{
		"login":    {dst: &p.LoginURL, raw: providerConfig.LoginURL},
		"redeem":   {dst: &p.RedeemURL, raw: providerConfig.RedeemURL},
		"profile":  {dst: &p.ProfileURL, raw: providerConfig.ProfileURL},
		"validate": {dst: &p.ValidateURL, raw: providerConfig.ValidateURL},
	} {
		var err error
		*u.dst, err = url.Parse(u.raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("could not parse %s URL: %v", name, err))
		}
	}
	return errs
}
