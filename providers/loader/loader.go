package loader

import (
	"context"
	"fmt"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers/loader/configloader"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers/loader/postgres"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers/loader/single"
)

type Loader interface {
	// id is provider id, which should be same as providerId
	Load(ctx context.Context, id string) (providers.Provider, error)
}

// factory function for types.Loader interface
func NewLoader(opts *options.Options) (Loader, error) {
	conf := opts.ProviderLoader
	switch conf.Type {
	case "config":
		return configloader.New(opts.Providers)
	case "", "single": // default set to single provider loaded from config
		return single.New(opts.Providers[0])
	case "postgres":
		return postgres.New(*opts.ProviderLoader.PostgresLoader, opts.ProxyPrefix)
	default:
		return nil, fmt.Errorf("invalid provider loader type '%s'", conf.Type)
	}
}
