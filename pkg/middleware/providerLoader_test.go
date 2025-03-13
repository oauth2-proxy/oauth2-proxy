package middleware

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers/loader"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers/loader/configloader"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers/utils"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/stretchr/testify/assert"
)

func TestProviderLoader(t *testing.T) {

	rw := httptest.NewRecorder()
	req := httptest.NewRequest("", "/", nil)

	ctx := utils.AppendProviderIDToContext(req.Context(), "dummy")
	req = req.WithContext(ctx)

	req2 := httptest.NewRequest("", "/", nil)
	ctx2 := utils.AppendProviderIDToContext(req2.Context(), "xxxx")
	req2 = req2.WithContext(ctx2)
	l, _ := configloader.New(options.Providers{
		{
			ID:   "dummy",
			Type: "keycloak",
		},
	})

	wantProvider, _ := providers.NewProvider(options.Provider{
		ID:   "dummy",
		Type: "keycloak",
	})

	tests := []struct {
		name         string
		l            loader.Loader
		req          *http.Request
		wantProvider providers.Provider
	}{
		{
			"Providerloader with valid loader",
			l,
			req,
			wantProvider,
		},
		{
			"Providerloader with invalid loader not found",
			l,
			req2,
			nil,
		},
	}

	for _, tt := range tests {
		var gotProvider providers.Provider
		t.Run(tt.name, func(t *testing.T) {
			handler := NewProviderLoader(tt.l)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

				gotProvider = utils.ProviderFromContext(r.Context())
			}))

			handler.ServeHTTP(rw, tt.req)
			assert.Equal(t, tt.wantProvider, gotProvider)
			if !reflect.DeepEqual(gotProvider, tt.wantProvider) {
				t.Errorf("provider loader  = %v, want %v", gotProvider, tt.wantProvider)
			}

		})
	}

}
