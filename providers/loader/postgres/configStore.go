package postgres

import "context"

// This is an interface defined for any store to hold configurations.
// The config store can of any type like postgres or redis.
type ConfigStore interface {
	Create(ctx context.Context, id string, providerConfig []byte) error
	Update(ctx context.Context, id string, providerConfig []byte) error
	Get(ctx context.Context, id string) (string, error)
	Delete(ctx context.Context, id string) error
}
