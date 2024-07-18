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
	)
})
