package validation

import (
	"fmt"
	"io/ioutil"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
)

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

	if provider.ProviderID == "" {
		msgs = append(msgs, "provider has empty id: ids are required for all providers")
	}

	// Ensure provider IDs are unique
	if _, ok := providerIDs[provider.ProviderID]; ok {
		msgs = append(msgs, fmt.Sprintf("multiple providers found with id %s: provider ids must be unique", provider.ProviderID))
	}
	providerIDs[provider.ProviderID] = struct{}{}

	if provider.ClientID == "" {
		msgs = append(msgs, "provider missing setting: client-id")
	}

	// login.gov uses a signed JWT to authenticate, not a client-secret
	if provider.ProviderType != "login.gov" {
		if provider.ClientSecret == "" && provider.ClientSecretFile == "" {
			msgs = append(msgs, "missing setting: client-secret or client-secret-file")
		}
		if provider.ClientSecret == "" && provider.ClientSecretFile != "" {
			_, err := ioutil.ReadFile(provider.ClientSecretFile)
			if err != nil {
				msgs = append(msgs, "could not read client secret file: "+provider.ClientSecretFile)
			}
		}
	}

	msgs = append(msgs, validateGoogleConfig(provider)...)

	return msgs
}

func validateGoogleConfig(provider options.Provider) []string {
	msgs := []string{}
	if provider.GoogleConfig.GoogleAdminEmail != "" ||
		provider.GoogleConfig.GoogleServiceAccountJSON != "" {
		if provider.GoogleConfig.GoogleAdminEmail == "" {
			msgs = append(msgs, "missing setting: google-admin-email")
		}
		if provider.GoogleConfig.GoogleServiceAccountJSON == "" {
			msgs = append(msgs, "missing setting: google-service-account-json")
		}
	}
	return msgs
}
