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

// An implementation of configStore interface, defined for testing scenarios where
// one can mock these functions and perform robust testing.
type fakeConfigStore struct {
	CreateFunc func(ctx context.Context, id string, providerConfig []byte) error
	UpdateFunc func(ctx context.Context, id string, providerConfig []byte) error
	GetFunc    func(ctx context.Context, id string) (string, error)
	DeleteFunc func(ctx context.Context, id string) error
}

// This function calls any implementation of create defined by fakeConfigStore.
func (f fakeConfigStore) Create(ctx context.Context, id string, providerConfig []byte) error {
	if f.CreateFunc != nil {
		return f.CreateFunc(ctx, id, providerConfig)
	}
	return nil
}

// Function below looks for implementation of Update func and returns nil if not found.
func (f fakeConfigStore) Update(ctx context.Context, id string, providerConfig []byte) error {
	if f.UpdateFunc != nil {
		return f.UpdateFunc(ctx, id, providerConfig)
	}
	return nil
}

// Get implements ConfigStore interface func Get and returns nil if no
// implementation is found.
func (f fakeConfigStore) Get(ctx context.Context, id string) (string, error) {
	if f.GetFunc != nil {
		return f.GetFunc(ctx, id)
	}
	return "", nil
}

// Delete implements interface for Delete func and return any implemented func
// else nil.
func (f fakeConfigStore) Delete(ctx context.Context, id string) error {
	if f.DeleteFunc != nil {
		return f.DeleteFunc(ctx, id)
	}
	return nil
}
