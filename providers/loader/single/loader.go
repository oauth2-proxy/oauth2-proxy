package single

import (
	"context"
	"fmt"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
)

type Loader struct {
	config   *options.Provider
	provider providers.Provider
}

func New(conf options.Provider) (*Loader, error) {
	provider, err := providers.NewProvider(conf)
	if err != nil {
		return nil, fmt.Errorf("unable to create new provider: %w", err)
	}
	return &Loader{
		config:   &conf,
		provider: provider,
	}, nil
}

func (l *Loader) Load(_ context.Context, _ string) (providers.Provider, error) {
	return l.provider, nil
}
