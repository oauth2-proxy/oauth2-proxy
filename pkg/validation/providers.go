package validation

import (
	"fmt"
	"io/ioutil"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
)

// validateMultipleProviders is the initial validation migration for multiple providrers
// It currently includes only logic which can verify the providers one by one and does not break the valdation pipe
func validateMultipleProviders(o *options.Options) []string {
	msgs := []string{}

	if len(o.Providers) == 0 {
		msgs = append(msgs, "at least one providers has to be defined")
	}

	if o.SkipProviderButton && len(o.Providers) > 1 {
		msgs = append(msgs, "SkipProviderButton and multiple providers are mutually exclusive")
	}

	providerIDs := make(map[string]string)
	for _, provider := range o.Providers {
		if provider.ProviderID == "" {
			msgs = append(msgs, "provider has empty id: ids are required for all providers")
		}

		// Ensure provider IDs are unique
		if _, ok := providerIDs[provider.ProviderID]; ok {
			msgs = append(msgs, fmt.Sprintf("multiple providers found with id %s: provider ids must be unique", provider.ProviderID))
		}
		providerIDs[provider.ProviderID] = ""

		if provider.ClientID == "" {
			msgs = append(msgs, fmt.Sprintf("provider missing setting: client-id"))
		}

		// login.gov uses a signed JWT to authenticate, not a client-secret
		if o.Providers[0].ProviderType != "login.gov" {
			if o.Providers[0].ClientSecret == "" && o.Providers[0].ClientSecretFile == "" {
				msgs = append(msgs, "missing setting: client-secret or client-secret-file")
			}
			if o.Providers[0].ClientSecret == "" && o.Providers[0].ClientSecretFile != "" {
				_, err := ioutil.ReadFile(o.Providers[0].ClientSecretFile)
				if err != nil {
					msgs = append(msgs, "could not read client secret file: "+o.Providers[0].ClientSecretFile)
				}
			}
		}

		if len(o.Providers[0].GoogleConfig.GoogleGroups) > 0 ||
			o.Providers[0].GoogleConfig.GoogleAdminEmail != "" ||
			o.Providers[0].GoogleConfig.GoogleServiceAccountJSON != "" {
			if len(o.Providers[0].GoogleConfig.GoogleGroups) < 1 {
				msgs = append(msgs, "missing setting: google-group")
			}
			if o.Providers[0].GoogleConfig.GoogleAdminEmail == "" {
				msgs = append(msgs, "missing setting: google-admin-email")
			}
			if o.Providers[0].GoogleConfig.GoogleServiceAccountJSON == "" {
				msgs = append(msgs, "missing setting: google-service-account-json")
			}
		}
	}
	return msgs
}
