package providerloader

import (
	"context"
	"fmt"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providerloader/configloader"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providerloader/postgres"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providerloader/single"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
)

type Loader interface {
	// id is provider id, which should be same as tenantId
	Load(ctx context.Context, id string) (providers.Provider, error)
}

// factory function for types.Loader interface
func NewLoader(opts *options.Options) (Loader, error) {
	conf := opts.ProviderLoader
	switch conf.Type {
	case "config":
		return configloader.New(opts.Providers)
	case "", "single": // empty value in case we're using legacy opts
		return single.New(opts.Providers[0])
	case "postgres":
		return postgres.New(*opts.ProviderLoader.PostgresLoader, opts.ProxyPrefix)
	default:
		return nil, fmt.Errorf("invalid tenant loader type '%s'", conf.Type)
	}
}
