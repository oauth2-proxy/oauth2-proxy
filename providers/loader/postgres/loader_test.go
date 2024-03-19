package postgres

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		conf    options.PostgresLoader
		want    *ProviderStore
		wantErr bool
	}{
		{
			"new config loader with error from postgres",
			options.PostgresLoader{
				Postgres: options.Postgres{},
			},
			nil,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.conf, "")
			fmt.Println(err)
			if err == nil && !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New config loader  = %v, want %v", got, tt.want)
			} else if err != nil && !tt.wantErr {
				t.Errorf("New config loader, got error: '%v'", err)
			}
		})
	}

}
func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		mockGet func(ctx context.Context, id string) (string, error)
		wantErr bool
	}{
		{
			"Load func test with no error",
			"dummy",
			func(ctx context.Context, id string) (string, error) {
				return "{\"id\":\"dummy\",\"provider\":\"keycloak\"}", nil
			},
			false,
		},
		{
			"Load func test with error returned ",
			"xxxx",
			func(ctx context.Context, id string) (string, error) {
				return "", fmt.Errorf("error")
			},
			true,
		},
		{
			"Load func test with error returned ",
			"",
			func(ctx context.Context, id string) (string, error) {
				return "{\"id\":\"dummy\",\"provider\":\"keycloak\"}", fmt.Errorf("error")
			},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ps := ProviderStore{
				opts: options.PostgresLoader{},
				configStore: fakeConfigStore{
					GetFunc: tt.mockGet,
				},
			}
			ctx := context.Background()
			_, err := ps.Load(ctx, tt.id)
			if err != nil && !tt.wantErr {
				t.Errorf("load, got error: '%v'", err)
			}
		})
	}
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
