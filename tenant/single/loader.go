package single

import (
	"fmt"
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
	"github.com/oauth2-proxy/oauth2-proxy/v7/tenant/types"
)

type loader struct {
	config *Configuration
	tenant *types.Tenant
}

func New(conf Configuration) (*loader, error) {
	provider, err := providers.NewProvider(*conf.Provider)
	if err != nil {
		return nil, fmt.Errorf("unable to create new provider: %w", err)
	}
	return &loader{
		config: &conf,
		tenant: &types.Tenant{
			Id:       "",
			Provider: provider,
		},
	}, nil
}

func (l *loader) Load(_ *http.Request) (*types.Tenant, error) {
	return l.tenant, nil
}

func (l *loader) LoadById(_ string) (*types.Tenant, error) {
	return l.tenant, nil
}
