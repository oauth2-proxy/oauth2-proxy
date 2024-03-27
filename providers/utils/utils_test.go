package utils

import (
	"context"
	"reflect"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
)

func TestProviderIDFromContext(t *testing.T) {

	tests := []struct {
		name string
		ctx  context.Context
		want string
	}{
		{"From context with valid key",
			context.WithValue(context.Background(), providerIDKey, "id"),
			"id",
		},
		{
			"From context with invalid key",
			context.WithValue(context.Background(), contextKey("xyfyuh"), "id"),
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ProviderIDFromContext(tt.ctx)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("from context = %v, want %v", got, tt.want)
			}
		})
	}

}

func TestInjectProviderID(t *testing.T) {
	tests := []struct {
		name       string
		providerid string
		uri        string
		want       string
	}{
		{
			"inject provider id",
			"dummyprovider",
			"file:website.com/pathtofile/intro.pdf",
			"file:website.com/pathtofile/intro.pdf?provider-id=dummyprovider",
		},
		{
			"inject empty provider id",
			"",
			"file:website.com/pathtofile/intro.pdf",
			"file:website.com/pathtofile/intro.pdf",
		},
		{
			"inject provider id with invalid url",
			"",
			"xxxxx",
			"xxxxx",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InjectProviderID(tt.providerid, tt.uri)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("inject providerid  = %v, want %v", got, tt.want)
			}
		})
	}

}

func TestProviderFromContext(t *testing.T) {
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

	for i, tt := range tests {
		if i != 0 {
			continue
		}
		t.Run(tt.name, func(t *testing.T) {
			got := ProviderFromContext(tt.ctx)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("from context = %v, want %v", got, tt.want)
			}
		})
	}

}
