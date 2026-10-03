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

	validBitbucketDataCenterProvider := options.Provider{
		Type:         "bitbucket",
		ID:           "ProviderIDBitbucketDC",
		ClientID:     "ClientID",
		ClientSecret: "ClientSecret",
		BitbucketConfig: options.BitbucketOptions{
			DataCenterURL: "https://bitbucket.example.com/bitbucket",
			Workspace:     "PROJ",
			Repository:    "PROJ/repo",
		},
	}

	invalidBitbucketDataCenterProvider := options.Provider{
		Type:         "bitbucket",
		ID:           "ProviderIDBitbucketDCInvalid",
		ClientID:     "ClientID",
		ClientSecret: "ClientSecret",
		BitbucketConfig: options.BitbucketOptions{
			DataCenterURL: "bitbucket.example.com",
			Repository:    "repo",
		},
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
	invalidBitbucketDataCenterURLMsg := "invalid setting: bitbucket-datacenter-url \"bitbucket.example.com\" must be an absolute http(s) URL"
	invalidBitbucketDataCenterRepoMsg := "invalid setting: bitbucket-repository \"repo\" must be PROJECTKEY/repo-slug when bitbucket-datacenter-url is set"
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
		Entry("with a valid Bitbucket Data Center config", &validateProvidersTableInput{
			options: &options.Options{
				Providers: options.Providers{
					validBitbucketDataCenterProvider,
				},
			},
			errStrings: []string{},
		}),
		Entry("with an invalid Bitbucket Data Center config", &validateProvidersTableInput{
			options: &options.Options{
				Providers: options.Providers{
					invalidBitbucketDataCenterProvider,
				},
			},
			errStrings: []string{invalidBitbucketDataCenterURLMsg, invalidBitbucketDataCenterRepoMsg},
		}),
	)
})
