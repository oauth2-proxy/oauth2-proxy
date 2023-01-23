package providerloader

import (
	"fmt"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providerloader/configloader"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providerloader/single"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
)

type Loader interface {
	// id is provider id, which should be same as tenantId
	Load(id string) (providers.Provider, error)
}

// factory function for types.Loader interface
func NewLoader(opts *options.Options) (Loader, error) {
	conf := opts.ProviderLoader
	switch conf.Type {
	case "config":
		return configloader.New(opts.Providers)
	case "", "single": // empty value in case we're using legacy opts
		return single.New(opts.Providers[0])
	default:
		return nil, fmt.Errorf("invalid tenant loader type '%s'", conf.Type)
	}
}
