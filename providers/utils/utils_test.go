package utils

import (
	"context"
	"reflect"
	"testing"
)

func TestFromContext(t *testing.T) {

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
			got := FromContext(tt.ctx)
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
