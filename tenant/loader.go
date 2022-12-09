package tenant

import (
	"fmt"

	"github.com/oauth2-proxy/oauth2-proxy/v7/tenant/configloader"
	"github.com/oauth2-proxy/oauth2-proxy/v7/tenant/single"
	"github.com/oauth2-proxy/oauth2-proxy/v7/tenant/types"
)

// factory function for types.Loader interface
func NewLoader(conf *LoaderConfiguration) (types.Loader, error) {
	switch conf.Type {
	case "config":
		return configloader.New(conf.Config)
	case "single":
		return single.New(*conf.Single)
	default:
		return nil, fmt.Errorf("invalid tenant loader type '%s'", conf.Type)
	}
}
