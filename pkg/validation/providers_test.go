package validation

import (
	"fmt"
	"os"
	"path/filepath"

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

	Context("with a client assertion file", func() {
		var assertionFile string

		BeforeEach(func() {
			assertionFile = filepath.Join(GinkgoT().TempDir(), "token")
			Expect(os.WriteFile(assertionFile, []byte("assertion"), 0600)).To(Succeed())
		})

		assertionProvider := func(providerType options.ProviderType, file string) options.Provider {
			return options.Provider{
				ID:                  "ProviderIDAssertion",
				Type:                providerType,
				ClientID:            "ClientID",
				ClientAssertionFile: file,
			}
		}

		validate := func(provider options.Provider) []string {
			return validateProviders(&options.Options{Providers: options.Providers{provider}})
		}

		It("does not require a client secret", func() {
			Expect(validate(assertionProvider(options.OIDCProvider, assertionFile))).To(BeEmpty())
		})

		It("is accepted by the keycloak-oidc provider", func() {
			Expect(validate(assertionProvider(options.KeycloakOIDCProvider, assertionFile))).To(BeEmpty())
		})

		It("rejects a client secret set alongside it", func() {
			provider := assertionProvider(options.OIDCProvider, assertionFile)
			provider.ClientSecret = "ClientSecret"

			Expect(validate(provider)).To(ConsistOf(
				"provider ProviderIDAssertion: client-assertion-file is mutually exclusive with client-secret and client-secret-file",
			))
		})

		It("rejects a client secret file set alongside it", func() {
			provider := assertionProvider(options.OIDCProvider, assertionFile)
			provider.ClientSecretFile = filepath.Join(GinkgoT().TempDir(), "client-secret")
			Expect(os.WriteFile(provider.ClientSecretFile, []byte("secret"), 0600)).To(Succeed())

			Expect(validate(provider)).To(ConsistOf(
				"provider ProviderIDAssertion: client-assertion-file is mutually exclusive with client-secret and client-secret-file",
			))
		})

		It("rejects unsupported providers", func() {
			for _, providerType := range []options.ProviderType{
				options.MicrosoftEntraIDProvider,
				options.GoogleProvider,
				options.GitLabProvider,
				options.ADFSProvider,
				options.CidaasProvider,
			} {
				Expect(validate(assertionProvider(providerType, assertionFile))).To(ConsistOf(
					fmt.Sprintf("provider ProviderIDAssertion: client-assertion-file is not supported by the %q provider", providerType),
				), string(providerType))
			}
		})

		It("rejects an unreadable file", func() {
			Expect(validate(assertionProvider(options.OIDCProvider, "/does/not/exist"))).To(ConsistOf(
				"could not read client assertion file: /does/not/exist",
			))
		})
	})
})
