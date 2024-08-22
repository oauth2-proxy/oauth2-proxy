package options

import (
	"fmt"
)

type LegacyOptions struct {
	// Legacy options for single provider
	LegacyProvider LegacyProvider `mapstructure:",squash"`

	Options Options `mapstructure:",squash"`
}

func NewLegacyOptions() *LegacyOptions {
	return &LegacyOptions{
		LegacyProvider: legacyProviderDefaults(),
		Options:        *NewOptions(),
	}
}

func (l *LegacyOptions) ToOptions() (*Options, error) {

	providers, err := l.LegacyProvider.convert()
	if err != nil {
		return nil, fmt.Errorf("error converting provider: %v", err)
	}
	l.Options.Providers = providers

	return &l.Options, nil
}

type LegacyProvider struct {
	ClientID                           string   `mapstructure:"client_id"`
	ClientSecret                       string   `mapstructure:"client_secret"`
	ProviderType                       string   `mapstructure:"provider"`
	OIDCIssuerURL                      string   `mapstructure:"oidc_issuer_url"`
	InsecureOIDCSkipIssuerVerification bool     `mapstructure:"insecure_oidc_skip_issuer_verification"`
	InsecureOIDCSkipNonce              bool     `mapstructure:"insecure_oidc_skip_nonce"`
	SkipOIDCDiscovery                  bool     `mapstructure:"skip_oidc_discovery"`
	OIDCJwksURL                        string   `mapstructure:"oidc_jwks_url"`
	OIDCEmailClaim                     string   `mapstructure:"oidc_email_claim"`
	OIDCGroupsClaim                    string   `mapstructure:"oidc_groups_claim"`
	OIDCAudienceClaims                 []string `mapstructure:"oidc_audience_claims"`
	OIDCExtraAudiences                 []string `mapstructure:"oidc_extra_audiences"`
	OIDCVerifierRequestTimeout         uint32   `mapstructure:"oidc_verifier_request_timeout"`
	LoginURL                           string   `mapstructure:"login_url"`
	RedeemURL                          string   `mapstructure:"redeem_url"`
	RedeemTimeout                      uint32   `mapstructure:"redeem_timeout"`
	ProfileURL                         string   `mapstructure:"profile_url"`
	SkipClaimsFromProfileURL           bool     `mapstructure:"skip_claims_from_profile_url"`
	ValidateURL                        string   `mapstructure:"validate_url"`
	Scope                              string   `mapstructure:"scope"`
	Prompt                             string   `mapstructure:"prompt"`
	ApprovalPrompt                     string   `mapstructure:"approval_prompt"`
	UserIDClaim                        string   `mapstructure:"user_id_claim"`
	AllowedGroups                      []string `mapstructure:"allowed_groups"`
	AcrValues                          string   `mapstructure:"acr_values"`
	CodeChallengeMethod                string   `mapstructure:"code_challenge_method"`
}

func legacyProviderDefaults() LegacyProvider {
	return LegacyProvider{
		ClientID:                           "",
		ClientSecret:                       "",
		ProviderType:                       "oidc",
		OIDCIssuerURL:                      "",
		InsecureOIDCSkipIssuerVerification: false,
		InsecureOIDCSkipNonce:              true,
		SkipOIDCDiscovery:                  false,
		OIDCJwksURL:                        "",
		OIDCEmailClaim:                     OIDCEmailClaim,
		OIDCGroupsClaim:                    OIDCGroupsClaim,
		OIDCAudienceClaims:                 []string{"aud"},
		OIDCExtraAudiences:                 nil,
		OIDCVerifierRequestTimeout:         2000,
		LoginURL:                           "",
		RedeemURL:                          "",
		ProfileURL:                         "",
		SkipClaimsFromProfileURL:           false,
		ValidateURL:                        "",
		Scope:                              "",
		Prompt:                             "",
		ApprovalPrompt:                     "",
		UserIDClaim:                        OIDCEmailClaim,
		AllowedGroups:                      nil,
		AcrValues:                          "",
		CodeChallengeMethod:                "",
	}
}

func (l *LegacyProvider) convert() (Providers, error) {
	providers := Providers{}

	provider := Provider{
		ClientID:                 l.ClientID,
		ClientSecret:             l.ClientSecret,
		Type:                     ProviderType(l.ProviderType),
		LoginURL:                 l.LoginURL,
		RedeemURL:                l.RedeemURL,
		ProfileURL:               l.ProfileURL,
		SkipClaimsFromProfileURL: l.SkipClaimsFromProfileURL,
		ValidateURL:              l.ValidateURL,
		Scope:                    l.Scope,
		AllowedGroups:            l.AllowedGroups,
		CodeChallengeMethod:      l.CodeChallengeMethod,
		RedeemTimeout:            l.RedeemTimeout,
	}

	// This part is out of the switch section for all providers that support OIDC
	provider.OIDCConfig = OIDCOptions{
		IssuerURL:                      l.OIDCIssuerURL,
		InsecureSkipIssuerVerification: l.InsecureOIDCSkipIssuerVerification,
		InsecureSkipNonce:              l.InsecureOIDCSkipNonce,
		SkipDiscovery:                  l.SkipOIDCDiscovery,
		JwksURL:                        l.OIDCJwksURL,
		UserIDClaim:                    l.UserIDClaim,
		EmailClaim:                     l.OIDCEmailClaim,
		GroupsClaim:                    l.OIDCGroupsClaim,
		AudienceClaims:                 l.OIDCAudienceClaims,
		ExtraAudiences:                 l.OIDCExtraAudiences,
		VerifierRequestTimeout:         l.OIDCVerifierRequestTimeout,
	}

	provider.ID = l.ProviderType + "=" + l.ClientID

	// handle AcrValues, Prompt and ApprovalPrompt
	var urlParams []LoginURLParameter
	if l.AcrValues != "" {
		urlParams = append(urlParams, LoginURLParameter{Name: "acr_values", Default: []string{l.AcrValues}})
	}
	switch {
	case l.Prompt != "":
		urlParams = append(urlParams, LoginURLParameter{Name: "prompt", Default: []string{l.Prompt}})
	case l.ApprovalPrompt != "":
		urlParams = append(urlParams, LoginURLParameter{Name: "approval_prompt", Default: []string{l.ApprovalPrompt}})
	}

	provider.LoginURLParameters = urlParams

	providers = append(providers, provider)

	return providers, nil
}
