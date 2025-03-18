package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
)

type ProviderStore struct {
	opts        options.PostgresLoader
	configStore ConfigStore
}

func New(opts options.PostgresLoader, proxyPrefix string) (*ProviderStore, error) {

	configStore, err := initializeConfigStore(opts)
	if err != nil {
		return nil, err
	}
	err = NewAPI(opts.API, configStore, proxyPrefix)
	if err != nil {
		return nil, err
	}

	l := ProviderStore{
		opts:        opts,
		configStore: configStore,
	}
	return &l, nil
}

func (ps *ProviderStore) Load(ctx context.Context, id string) (providers.Provider, error) {
	if id == "" {
		return nil, fmt.Errorf("provider id is empty")
	}

	data, err := ps.configStore.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	provider, err := providerFromConfig(data)
	if err != nil {
		return nil, err
	}

	return provider, nil
}

func providerFromConfig(providerJSON string) (providers.Provider, error) {
	providerConf := options.Provider{}
	err := json.Unmarshal([]byte(providerJSON), &providerConf)
	if err != nil {
		return nil, fmt.Errorf("can't unmarshal into provider config struct: %w", err)
	}

	provider, err := providers.NewProvider(providerConf)
	if err != nil {
		return nil, fmt.Errorf("invalid provider config(id=%s): %s", providerConf.ID, err.Error())
	}
	return provider, nil
}

func applyEncryptionDecorator(secret string, cs ConfigStore) (ConfigStore, error) {
	cstd, err := encryption.NewCFBCipher([]byte(secret))
	if err != nil {
		return nil, fmt.Errorf("unable to create cipher from secret: %w", err)
	}
	cb64 := encryption.NewBase64Cipher(cstd)

	enDecorator, err := EncryptionDecorator(cs, cb64)
	if err != nil {
		return nil, err
	}
	return enDecorator, nil
}

func initializeConfigStore(opts options.PostgresLoader) (ConfigStore, error) {
	ps, err := NewPostgresStore(opts.Postgres)
	if err != nil {
		return nil, err
	}

	rs, err := NewRedisStore(opts.Redis, ps)
	if err != nil {
		return nil, err
	}

	enDecorator, err := applyEncryptionDecorator(opts.Secret, rs)
	if err != nil {
		return nil, err
	}
	return enDecorator, nil
}
