package tenantutils

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
			context.WithValue(context.Background(), tenantIDKey, "id"),
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

func TestInjectTenantID(t *testing.T) {
	tests := []struct {
		name     string
		tenantid string
		uri      string
		want     string
	}{
		{
			"inject tenant id",
			"dummytenant",
			"file:website.com/pathtofile/intro.pdf",
			"file:website.com/pathtofile/intro.pdf?tenant-id=dummytenant",
		},
		{
			"inject empty tenant id",
			"",
			"file:website.com/pathtofile/intro.pdf",
			"file:website.com/pathtofile/intro.pdf",
		},
		{
			"inject tenant id with invalid url",
			"",
			"xxxxx",
			"xxxxx",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := InjectTenantID(tt.tenantid, tt.uri)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("inject tenantid  = %v, want %v", got, tt.want)
			}
		})
	}

}
