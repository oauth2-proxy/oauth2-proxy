package validation

import (
	"fmt"

	"github.com/Jing-ze/oauth2-proxy/pkg/apis/options"
)

// validateProviders is the initial validation migration for multiple providrers
// It currently includes only logic that can verify the providers one by one and does not break the valdation pipe
func validateProviders(o *options.Options) []string {
	msgs := []string{}

	// validate general multiple provider configuration
	if len(o.Providers) == 0 {
		msgs = append(msgs, "at least one provider has to be defined")
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

	// login.gov uses a signed JWT to authenticate, not a client-secret
	if provider.Type != "login.gov" {
		if provider.ClientSecret == "" {
			msgs = append(msgs, "missing setting: client-secret or client-secret-file")
		}
	}

	return msgs
}
