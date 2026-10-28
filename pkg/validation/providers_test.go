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
		GrantTypes:   []string{"authorization_code"},
	}

	validProviderDeviceGrantOnly := options.Provider{
		ID:           "ProviderIDDeviceGrantOnly",
		ClientID:     "ClientID",
		ClientSecret: "ClientSecret",
		GrantTypes:   []string{"urn:ietf:params:oauth:grant-type:device_code"},
	}
	validProviderDivecGrantAndAuthorizationCode := options.Provider{
		ID:           "ProviderIDAuthCodeAndDeviceGrant",
		ClientID:     "ClientID",
		ClientSecret: "ClientSecret",
		GrantTypes:   []string{"authorization_code", "urn:ietf:params:oauth:grant-type:device_code"},
	}

	validOIDCSigningAlgorithmsProvider := options.Provider{
		ID:           "ProviderIDOIDCSigningAlgorithms",
		ClientID:     "ClientID",
		ClientSecret: "ClientSecret",
		GrantTypes:   []string{"authorization_code"},
		OIDCConfig: options.OIDCOptions{
			EnabledSigningAlgs: []string{"RS256", "EdDSA"},
		},
	}

	invalidOIDCSigningAlgorithmsProvider := options.Provider{
		ID:           "ProviderIDInvalidOIDCSigningAlgorithms",
		ClientID:     "ClientID",
		ClientSecret: "ClientSecret",
		GrantTypes:   []string{"authorization_code"},
		OIDCConfig: options.OIDCOptions{
			EnabledSigningAlgs: []string{"RS256", "invalid"},
		},
	}

	invalidOIDCSigningAlgorithmCaseProvider := options.Provider{
		ID:           "ProviderIDInvalidOIDCSigningAlgorithmCase",
		ClientID:     "ClientID",
		ClientSecret: "ClientSecret",
		GrantTypes:   []string{"authorization_code"},
		OIDCConfig: options.OIDCOptions{
			EnabledSigningAlgs: []string{"rs256"},
		},
	}

	validLoginGovProvider := options.Provider{
		Type:         "login.gov",
		ID:           "ProviderIDLoginGov",
		ClientID:     "ClientID",
		ClientSecret: "ClientSecret",
		GrantTypes:   []string{"authorization_code"},
	}

	missingIDProvider := options.Provider{
		ClientID:     "ClientID",
		ClientSecret: "ClientSecret",
		GrantTypes:   []string{"authorization_code"},
	}

	invalidProviderNoGrantTypes := options.Provider{
		ID:           "ProviderIDNoGrantTypes",
		ClientID:     "ClientID",
		ClientSecret: "ClientSecret",
		GrantTypes:   []string{},
	}
	invalidProviderGrantTypeEmptyString := options.Provider{
		ID:           "ProviderIDGrantTypeEmtpyString",
		ClientID:     "ClientID",
		ClientSecret: "ClientSecret",
		GrantTypes:   []string{""},
	}
	invalidProviderGrantTypeWithTypo := options.Provider{
		ID:           "ProviderIDGrantTypeWithTypo",
		ClientID:     "ClientID",
		ClientSecret: "ClientSecret",
		GrantTypes:   []string{"authoraization_code"},
	}

	missingProvider := "at least one provider has to be defined"
	emptyIDMsg := "provider has empty id: ids are required for all providers"
	duplicateProviderIDMsg := "multiple providers found with id ProviderID: provider ids must be unique"
	skipButtonAndMultipleProvidersMsg := "SkipProviderButton and multiple providers are mutually exclusive"
	invalidOIDCSigningAlgorithmMsg := "provider ProviderIDInvalidOIDCSigningAlgorithms has invalid EnabledSigningAlgs entry \"invalid\""
	invalidOIDCSigningAlgorithmCaseMsg := "provider ProviderIDInvalidOIDCSigningAlgorithmCase has invalid EnabledSigningAlgs entry \"rs256\""
	invalidProviderNoGrantTypesMsg := "provider ProviderIDNoGrantTypes has no grant type(s). Supported are: 'authorization_code', 'urn:ietf:params:oauth:grant-type:device_code'"
	invalidProviderGrantTypeWithTypeMsg := "provider ProviderIDGrantTypeWithTypo has invalid grant type 'authoraization_code'. Supported are: 'authorization_code', 'urn:ietf:params:oauth:grant-type:device_code'"
	invalidProviderGrantTypeEmptyStringMsg := "provider ProviderIDGrantTypeEmtpyString has invalid grant type ''. Supported are: 'authorization_code', 'urn:ietf:params:oauth:grant-type:device_code'"

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
					validProviderDeviceGrantOnly,
					validProviderDivecGrantAndAuthorizationCode,
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
		Entry("without grant types", &validateProvidersTableInput{
			options: &options.Options{
				Providers: options.Providers{
					invalidProviderNoGrantTypes,
				},
			},
			errStrings: []string{invalidProviderNoGrantTypesMsg},
		}),
		Entry("with empty string grant types", &validateProvidersTableInput{
			options: &options.Options{
				Providers: options.Providers{
					invalidProviderGrantTypeEmptyString,
				},
			},
			errStrings: []string{invalidProviderGrantTypeEmptyStringMsg},
		}),
		Entry("grant type with typo", &validateProvidersTableInput{
			options: &options.Options{
				Providers: options.Providers{
					invalidProviderGrantTypeWithTypo,
				},
			},
			errStrings: []string{invalidProviderGrantTypeWithTypeMsg},
		}),
	)
})
