package util

import (
	"context"
	"reflect"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
)

func TestFromContext(t *testing.T) {
	p, _ := providers.NewProvider(options.Provider{})
	tests := []struct {
		name string
		ctx  context.Context
		want providers.Provider
	}{
		{"From context with valid key",
			context.WithValue(context.Background(), providerKey, p),
			p,
		},
		{
			"From context with invalid key",
			context.WithValue(context.Background(), contextKey("gdyewiu"), "id"),
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FromContext(tt.ctx)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("from context = %v, want %v", got, tt.want)
			}
		})
	}

}
