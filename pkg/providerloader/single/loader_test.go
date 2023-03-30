package single

import (
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
		conf    options.Provider
		want    *Loader
		wantErr bool
	}{
		{
			"new config loader with no error",
			options.Provider{

				ID:   "dummy",
				Type: "xxxx",
			},
			nil,
			true,
		},
		{
			"new config loader with error returned",
			options.Provider{

				ID:   "dummy",
				Type: "keycloak",
			},
			&Loader{
				config: &options.Provider{

					ID:   "dummy",
					Type: "keycloak",
				},
				provider: prov,
			},
			false,
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
		config: &options.Provider{

			ID:   "dummy",
			Type: "keycloak",
		},
		provider: &providers.KeycloakProvider{},
	}
	tests := []struct {
		name    string
		id      string
		want    providers.Provider
		wantErr bool
	}{
		{
			"single provider load func with no error",
			"dummy",
			&providers.KeycloakProvider{},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _ := l.Load("")

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf(" load returned  = %v, want %v", got, tt.want)
			}
		})
	}
}
