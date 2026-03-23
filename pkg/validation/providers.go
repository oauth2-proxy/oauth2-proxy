package validation

import (
	"fmt"
	"os"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util/ptr"
)

var supportedOIDCSigningAlgorithms = map[jose.SignatureAlgorithm]struct{}{
	jose.EdDSA: {},
	jose.HS256: {},
	jose.HS384: {},
	jose.HS512: {},
	jose.RS256: {},
	jose.RS384: {},
	jose.RS512: {},
	jose.ES256: {},
	jose.ES384: {},
	jose.ES512: {},
	jose.PS256: {},
	jose.PS384: {},
	jose.PS512: {},
}

// validateProviders is the initial validation migration for multiple providrers
// It currently includes only logic that can verify the providers one by one and does not break the valdation pipe
func validateProviders(o *options.Options) []string {
	msgs := []string{}

	// validate general multiple provider configuration
	if len(o.Providers) == 0 {
		msgs = append(msgs, "at least one provider has to be defined")
	}
	if o.SkipProviderButton && len(o.Providers) > 1 {
		msgs = append(msgs, "SkipProviderButton and multiple providers are mutually exclusive")
	}

	providerIDs := make(map[string]struct{})

	for _, provider := range o.Providers {
		msgs = append(msgs, validateProvider(provider, providerIDs)...)
	}

	return msgs
}

func validateProvider(provider options.Provider, providerIDs map[string]struct{}) []string {
	msgs := []string{}

	if provider.ID == "" {
		msgs = append(msgs, "provider has empty id: ids are required for all providers")
	}

	// Ensure provider IDs are unique
	if _, ok := providerIDs[provider.ID]; ok {
		msgs = append(msgs, fmt.Sprintf("multiple providers found with id %s: provider ids must be unique", provider.ID))
	}
	providerIDs[provider.ID] = struct{}{}

	if provider.ClientID == "" {
		msgs = append(msgs, "provider missing setting: client-id")
	}

	if providerRequiresClientSecret(provider) {
		msgs = append(msgs, validateClientSecret(provider)...)
	}

	if provider.Type == "google" {
		msgs = append(msgs, validateGoogleConfig(provider)...)
	}

	if provider.Type == "entra-id" {
		msgs = append(msgs, validateEntraConfig(provider)...)
	}

	msgs = append(msgs, validateOIDCSigningAlgorithms(provider)...)

	return msgs
}

func validateOIDCSigningAlgorithms(provider options.Provider) []string {
	msgs := []string{}

	for _, algorithm := range provider.OIDCConfig.EnabledSigningAlgs {
		if _, ok := supportedOIDCSigningAlgorithms[jose.SignatureAlgorithm(algorithm)]; ok {
			continue
		}

		msgs = append(msgs, fmt.Sprintf("provider %s has invalid EnabledSigningAlgs entry %q", provider.ID, algorithm))
	}

	return msgs
}

// providerRequiresClientSecret checks if provider requires client secret to be set
// or it can be omitted in favor of JWT token to authenticate oAuth client
func providerRequiresClientSecret(provider options.Provider) bool {
	if provider.Type == "entra-id" && ptr.Deref(provider.MicrosoftEntraIDConfig.FederatedTokenAuth, options.DefaultMicrosoftEntraIDUseFederatedToken) {
		return false
	}

	if provider.Type == "login.gov" {
		return false
	}

	return true
}

func validateClientSecret(provider options.Provider) []string {
	msgs := []string{}

	if provider.ClientSecret == "" && provider.ClientSecretFile == "" {
		msgs = append(msgs, "missing setting: client-secret or client-secret-file")
	}
	if provider.ClientSecret == "" && provider.ClientSecretFile != "" {
		_, err := os.ReadFile(provider.ClientSecretFile)
		if err != nil {
			msgs = append(msgs, "could not read client secret file: "+provider.ClientSecretFile)
		}
	}

	return msgs
}

func validateGoogleConfig(provider options.Provider) []string {
	msgs := []string{}

	hasAdminEmail := provider.GoogleConfig.AdminEmail != ""
	hasSAJSON := provider.GoogleConfig.ServiceAccountJSON != ""
	useADC := ptr.Deref(provider.GoogleConfig.UseApplicationDefaultCredentials, options.DefaultUseApplicationDefaultCredentials)

	if !hasAdminEmail && !hasSAJSON && !useADC {
		return msgs
	}

	if !hasAdminEmail {
		msgs = append(msgs, "missing setting: google-admin-email")
	}

	_, err := os.Stat(provider.GoogleConfig.ServiceAccountJSON)
	if !useADC {
		if !hasSAJSON {
			msgs = append(msgs, "missing setting: google-service-account-json or google-use-application-default-credentials")
		} else if err != nil {
			msgs = append(msgs, fmt.Sprintf("Google credentials file not found: %s", provider.GoogleConfig.ServiceAccountJSON))
		}
	} else if hasSAJSON {
		msgs = append(msgs, "invalid setting: can't use both google-service-account-json and google-use-application-default-credentials")
	}

	return msgs
}

func validateEntraConfig(provider options.Provider) []string {
	msgs := []string{}

	if ptr.Deref(provider.MicrosoftEntraIDConfig.FederatedTokenAuth, options.DefaultMicrosoftEntraIDUseFederatedToken) {
		federatedTokenPath := os.Getenv("AZURE_FEDERATED_TOKEN_FILE")

		if federatedTokenPath == "" {
			msgs = append(msgs, "entra federated token authentication is enabled, but AZURE_FEDERATED_TOKEN_FILE variable is not set, check your workload identity configuration.")
			return msgs
		}

		// #nosec G703 -- AZURE_FEDERATED_TOKEN_FILE is set by the operator, not user input
		_, err := os.Stat(federatedTokenPath)
		if err != nil {
			msgs = append(msgs, "could not read entra federated token file")
		}
	}

	return msgs
}
