package configloader

import (
	"context"
	"reflect"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
)

func TestNew(t *testing.T) {
	prov, _ := providers.NewProvider(options.Provider{

		ID:   "dummy",
		Type: "keycloak",
	})
	tests := []struct {
		name    string
		conf    options.Providers
		want    *Loader
		wantErr bool
	}{
		{
			"new config loader with no error",
			options.Providers{
				{
					ID:   "dummy",
					Type: "keycloak",
				},
			},
			&Loader{
				providersConf: options.Providers{
					{
						ID:   "dummy",
						Type: "keycloak",
					},
				},
				providers: map[string]providers.Provider{
					"dummy": prov,
				},
			},
			false,
		},
		{
			"new config loader with error returned",
			options.Providers{
				{
					ID:   "",
					Type: "keycloak",
				},
			},
			nil,
			true,
		},
		{
			"config loader",
			options.Providers{
				{
					ID:   "dummy",
					Type: "xxxx",
				},
			},
			nil,
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := New(tt.conf)

			if err == nil && !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("New config loader  = %v, want %v", got, tt.want)
			} else if err != nil && !tt.wantErr {
				t.Errorf("New config loader, got error: '%v'", err)
			}
		})
	}

}

func TestLoad(t *testing.T) {
	l := &Loader{
		providersConf: options.Providers{
			{
				ID:   "dummy",
				Type: "keycloak",
			},
		},
		providers: map[string]providers.Provider{
			"dummy": &providers.KeycloakProvider{},
		},
	}
	tests := []struct {
		name    string
		id      string
		want    providers.Provider
		wantErr bool
	}{
		{
			"Load func test with no error",
			"dummy",
			&providers.KeycloakProvider{},
			false,
		},
		{
			"Load func test with error returned ",
			"xxxx",
			&providers.KeycloakProvider{},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			got, err := l.Load(ctx, tt.id)

			if err == nil && !tt.wantErr && !reflect.DeepEqual(got, tt.want) {
				t.Errorf(" load returned  = %v, want %v", got, tt.want)
			} else if err != nil && !tt.wantErr {
				t.Errorf("load, got error: '%v'", err)
			}
		})
	}
}
