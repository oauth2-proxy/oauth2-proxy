package single

import (
	"fmt"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
)

type loader struct {
	config   *options.Provider
	provider providers.Provider
}

func New(conf options.Provider) (*loader, error) {
	provider, err := providers.NewProvider(conf)
	if err != nil {
		return nil, fmt.Errorf("unable to create new provider: %w", err)
	}
	return &loader{
		config:   &conf,
		provider: provider,
	}, nil
}

func (l *loader) Load(_ string) (providers.Provider, error) {
	return l.provider, nil
}
