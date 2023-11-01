package validation

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

func newPrivateKeyBytes() ([]byte, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}
	b := &bytes.Buffer{}
	if err := pem.Encode(b, privateKeyBlock); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

var _ = Describe("Providers", func() {
	type validateProvidersTableInput struct {
		options    *options.Options
		errStrings []string
	}

	privateKeyBytes, err := newPrivateKeyBytes()
	Expect(err).ToNot(HaveOccurred())

	validClientSecretConfig := options.AuthenticationOptions{
		Method:       options.ClientSecret,
		ClientSecret: "ClientSecret",
	}

	validPrivateKeyConfig := options.AuthenticationOptions{
		Method:       options.PrivateKeyJWT,
		JWTAlgorithm: "RS256",
		JWTKey:       string(privateKeyBytes),
		JWTExpire:    1 * time.Hour,
		JWTKeyId:     "JWTKeyId",
	}

	validProvider := options.Provider{
		ID:                   "ProviderID",
		ClientID:             "ClientID",
		AuthenticationConfig: validClientSecretConfig,
	}

	validLoginGovProvider := options.Provider{
		Type:                 "login.gov",
		ID:                   "ProviderIDLoginGov",
		ClientID:             "ClientID",
		AuthenticationConfig: validPrivateKeyConfig,
	}

	missingIDProvider := options.Provider{
		ClientID:             "ClientID",
		AuthenticationConfig: validClientSecretConfig,
	}

	loginGovProviderWithInvalidAuthentication := options.Provider{
		Type:                 "login.gov",
		ID:                   "ProviderIDLoginGov",
		ClientID:             "ClientID",
		AuthenticationConfig: validClientSecretConfig,
	}

	missingProvider := "at least one provider has to be defined"
	emptyIDMsg := "provider has empty id: ids are required for all providers"
	duplicateProviderIDMsg := "multiple providers found with id ProviderID: provider ids must be unique"
	skipButtonAndMultipleProvidersMsg := "SkipProviderButton and multiple providers are mutually exclusive"
	invalidLoginGovAuthentication := "login.gov configuration not using private key jwt"

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
		Entry("login.gov configuration not using private key jwt", &validateProvidersTableInput{
			options: &options.Options{
				Providers: options.Providers{
					loginGovProviderWithInvalidAuthentication,
				},
			},
			errStrings: []string{invalidLoginGovAuthentication},
		}),
	)
})
