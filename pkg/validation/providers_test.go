package validation

import (
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Providers", func() {
	type validateProvidersTableInput struct {
		options    *options.Options
		errStrings []string
	}

	validProvider := options.Provider{
		ID:           "ProviderID",
		ClientID:     "ClientID",
		ClientSecret: "ClientSecret",
	}

	validOIDCSigningAlgorithmsProvider := options.Provider{
		ID:           "ProviderIDOIDCSigningAlgorithms",
		ClientID:     "ClientID",
		ClientSecret: "ClientSecret",
		OIDCConfig: options.OIDCOptions{
			EnabledSigningAlgs: []string{"RS256", "EdDSA"},
		},
	}

	invalidOIDCSigningAlgorithmsProvider := options.Provider{
		ID:           "ProviderIDInvalidOIDCSigningAlgorithms",
		ClientID:     "ClientID",
		ClientSecret: "ClientSecret",
		OIDCConfig: options.OIDCOptions{
			EnabledSigningAlgs: []string{"RS256", "invalid"},
		},
	}

	invalidOIDCSigningAlgorithmCaseProvider := options.Provider{
		ID:           "ProviderIDInvalidOIDCSigningAlgorithmCase",
		ClientID:     "ClientID",
		ClientSecret: "ClientSecret",
		OIDCConfig: options.OIDCOptions{
			EnabledSigningAlgs: []string{"rs256"},
		},
	}

	validLoginGovProvider := options.Provider{
		Type:         "login.gov",
		ID:           "ProviderIDLoginGov",
		ClientID:     "ClientID",
		ClientSecret: "ClientSecret",
	}

	missingIDProvider := options.Provider{
		ClientID:     "ClientID",
		ClientSecret: "ClientSecret",
	}

	removedUserIDClaimProvider := options.Provider{
		ID:           "ProviderIDRemovedUserIDClaim",
		ClientID:     "ClientID",
		ClientSecret: "ClientSecret",
		OIDCConfig: options.OIDCOptions{
			UserIDClaim: "sub", //nolint:staticcheck // deliberately setting the removed option to assert it is rejected
		},
	}

	redundantUserIDClaimProvider := options.Provider{
		ID:           "ProviderIDRedundantUserIDClaim",
		ClientID:     "ClientID",
		ClientSecret: "ClientSecret",
		OIDCConfig: options.OIDCOptions{
			UserIDClaim: "email", //nolint:staticcheck // deliberately setting the removed option to assert it is rejected
		},
	}

	missingProvider := "at least one provider has to be defined"
	emptyIDMsg := "provider has empty id: ids are required for all providers"
	duplicateProviderIDMsg := "multiple providers found with id ProviderID: provider ids must be unique"
	skipButtonAndMultipleProvidersMsg := "SkipProviderButton and multiple providers are mutually exclusive"
	invalidOIDCSigningAlgorithmMsg := "provider ProviderIDInvalidOIDCSigningAlgorithms has invalid EnabledSigningAlgs entry \"invalid\""
	invalidOIDCSigningAlgorithmCaseMsg := "provider ProviderIDInvalidOIDCSigningAlgorithmCase has invalid EnabledSigningAlgs entry \"rs256\""
	removedUserIDClaimMsg := "provider ProviderIDRemovedUserIDClaim: user-id-claim has been removed; use oidc-email-claim=sub instead (in alpha config: replace userIDClaim with emailClaim)"
	redundantUserIDClaimMsg := "provider ProviderIDRedundantUserIDClaim: user-id-claim has been removed and must be unset; it had no effect as oidc-email-claim already defaults to \"email\" (in alpha config: remove userIDClaim)"

	DescribeTable("validateProviders",
		func(o *validateProvidersTableInput) {
			Expect(validateProviders(o.options)).To(ConsistOf(o.errStrings))
		},
		Entry("with no providers", &validateProvidersTableInput{
			options:    &options.Options{},
			errStrings: []string{missingProvider},
		}),
		Entry("with valid providers", &validateProvidersTableInput{
			options: &options.Options{
				Providers: options.Providers{
					validProvider,
					validLoginGovProvider,
				},
			},
			errStrings: []string{},
		}),
		Entry("with an empty providerID", &validateProvidersTableInput{
			options: &options.Options{
				Providers: options.Providers{
					missingIDProvider,
				},
			},
			errStrings: []string{emptyIDMsg},
		}),
		Entry("with same providerID", &validateProvidersTableInput{
			options: &options.Options{
				Providers: options.Providers{
					validProvider,
					validProvider,
				},
			},
			errStrings: []string{duplicateProviderIDMsg},
		}),
		Entry("with multiple providers and skip provider button", &validateProvidersTableInput{
			options: &options.Options{
				SkipProviderButton: true,
				Providers: options.Providers{
					validProvider,
					validLoginGovProvider,
				},
			},
			errStrings: []string{skipButtonAndMultipleProvidersMsg},
		}),
		Entry("with valid OIDC signing algorithms", &validateProvidersTableInput{
			options: &options.Options{
				Providers: options.Providers{
					validOIDCSigningAlgorithmsProvider,
				},
			},
			errStrings: []string{},
		}),
		Entry("with an invalid OIDC signing algorithm", &validateProvidersTableInput{
			options: &options.Options{
				Providers: options.Providers{
					invalidOIDCSigningAlgorithmsProvider,
				},
			},
			errStrings: []string{invalidOIDCSigningAlgorithmMsg},
		}),
		Entry("with an OIDC signing algorithm using invalid casing", &validateProvidersTableInput{
			options: &options.Options{
				Providers: options.Providers{
					invalidOIDCSigningAlgorithmCaseProvider,
				},
			},
			errStrings: []string{invalidOIDCSigningAlgorithmCaseMsg},
		}),
		Entry("with the removed user-id-claim option set to a non-email claim", &validateProvidersTableInput{
			options: &options.Options{
				Providers: options.Providers{
					removedUserIDClaimProvider,
				},
			},
			errStrings: []string{removedUserIDClaimMsg},
		}),
		Entry("with the removed user-id-claim option set to the email claim", &validateProvidersTableInput{
			options: &options.Options{
				Providers: options.Providers{
					redundantUserIDClaimProvider,
				},
			},
			errStrings: []string{redundantUserIDClaimMsg},
		}),
	)
})
