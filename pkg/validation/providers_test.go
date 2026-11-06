package validation

import (
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util/ptr"
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

	missingProvider := "at least one provider has to be defined"
	emptyIDMsg := "provider has empty id: ids are required for all providers"
	duplicateProviderIDMsg := "multiple providers found with id ProviderID: provider ids must be unique"
	skipButtonAndMultipleProvidersMsg := "SkipProviderButton and multiple providers are mutually exclusive"
	invalidOIDCSigningAlgorithmMsg := "provider ProviderIDInvalidOIDCSigningAlgorithms has invalid EnabledSigningAlgs entry \"invalid\""
	invalidOIDCSigningAlgorithmCaseMsg := "provider ProviderIDInvalidOIDCSigningAlgorithmCase has invalid EnabledSigningAlgs entry \"rs256\""

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
	)
})

var _ = DescribeTable("Google group membership concurrency",
	func(concurrency *int, valid bool) {
		provider := options.Provider{GoogleConfig: options.GoogleOptions{GroupMembershipConcurrency: concurrency}}
		if valid {
			Expect(validateGoogleConfig(provider)).To(BeEmpty())
		} else {
			Expect(validateGoogleConfig(provider)).To(ConsistOf("google-group-membership-concurrency must be between 1 and 10"))
		}
	},
	Entry("unset", (*int)(nil), true),
	Entry("negative", ptr.To(-1), false),
	Entry("zero", ptr.To(0), false),
	Entry("minimum", ptr.To(1), true),
	Entry("default", ptr.To(5), true),
	Entry("maximum", ptr.To(10), true),
	Entry("above maximum", ptr.To(11), false),
)
