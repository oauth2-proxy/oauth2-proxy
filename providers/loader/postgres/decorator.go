package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
)

// this is a decorator/wrapper over ConfigStore
// it encrypts the client secret before storing in db and cache.
type encryptionDecorator struct {
	ConfigStore
	cipher encryption.Cipher
}

func EncryptionDecorator(c ConfigStore, cipher encryption.Cipher) (ConfigStore, error) {
	return &encryptionDecorator{
		ConfigStore: c,
		cipher:      cipher,
	}, nil
}

type encryptOrDecryptFunc func([]byte) ([]byte, error)
type createOrUpdateFunc func(ctx context.Context, id string, providerconf []byte) error

func encryptOrDecryptClientSecret(providerconf []byte, action encryptOrDecryptFunc) ([]byte, error) {
	var providerConf *options.Provider

	err := json.Unmarshal(providerconf, &providerConf)
	if err != nil {
		return nil, fmt.Errorf("json unmarshalling error: %w", err)
	}

	UpdatedSecret, err := action([]byte(providerConf.ClientSecret))
	if err != nil {
		return nil, err
	}
	providerConf.ClientSecret = string(UpdatedSecret)
	UpdateProviderconf, err := json.Marshal(providerConf)
	if err != nil {
		return nil, fmt.Errorf("json marshallig error: %w", err)
	}

	return UpdateProviderconf, nil
}

func (en *encryptionDecorator) Create(ctx context.Context, id string, providerconf []byte) error {
	return en.createOrUpdateConfig(ctx, id, providerconf, en.ConfigStore.Create)
}

func (en *encryptionDecorator) Update(ctx context.Context, id string, providerconf []byte) error {
	return en.createOrUpdateConfig(ctx, id, providerconf, en.ConfigStore.Update)
}

func (en *encryptionDecorator) createOrUpdateConfig(ctx context.Context, id string, providerconf []byte, f createOrUpdateFunc) error {
	updatedProviderconf, err := encryptOrDecryptClientSecret(providerconf, en.cipher.Encrypt)
	if err != nil {
		return fmt.Errorf("encryption error: %w", err)
	}
	return f(ctx, id, updatedProviderconf)
}

func (en *encryptionDecorator) Get(ctx context.Context, id string) (string, error) {
	providerconf, err := en.ConfigStore.Get(ctx, id)
	if err != nil {
		return "", err
	}

	updatedProviderconf, err := encryptOrDecryptClientSecret([]byte(providerconf), en.cipher.Decrypt)
	if err != nil {
		return "", err
	}

	return string(updatedProviderconf), nil
}
