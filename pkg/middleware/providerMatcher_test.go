package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	providermatcher "github.com/oauth2-proxy/oauth2-proxy/v7/providers/matcher"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers/utils"
)

func TestProviderMatcher(t *testing.T) {

	rw := httptest.NewRecorder()
	tm, _ := providermatcher.New(options.ProviderMatcher{
		Rules: []options.ProviderMatcherRule{
			{
				Source:       options.ProviderMatcherRuleSourceQueryParams,
				QueryParam:   "providerid",
				Expr:         ".*",
				CaptureGroup: 0,
			},
			{

				Source:       options.ProviderMatcherRuleSourceHost,
				Expr:         ".*",
				CaptureGroup: 0,
			},
			{
				Source:       options.ProviderMatcherRuleSourcePath,
				Expr:         ".*",
				CaptureGroup: 0,
			},
			{
				Source:       options.ProviderMatcherRuleSourceHeader,
				Expr:         ".*",
				CaptureGroup: 0,
				Header:       "Providerid",
			},
		},
	})

	tests := []struct {
		name string
		want string
		req  *http.Request
	}{
		{"provider matcher query",
			"id",
			&http.Request{
				URL: &url.URL{
					RawQuery: url.Values{
						"providerid": {"id"},
					}.Encode(),
				},
			},
		},
		{
			"provider matcher host",
			"dummy",
			&http.Request{
				Host: "dummy",
				URL:  &url.URL{},
			},
		},
		{
			"provider matcher path",
			"provider",
			&http.Request{
				URL: &url.URL{
					Path: "provider",
				},
			},
		},
		{
			"provider matcher header",
			"dummyprovider",
			&http.Request{
				URL: &url.URL{},
				Header: http.Header{
					"Providerid": {"dummyprovider"},
				},
			},
		},
	}

	for _, tt := range tests {
		var gotProvider string
		t.Run(tt.name, func(t *testing.T) {
			handler := NewProviderMatcher(tm)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

				gotProvider = utils.FromContext(r.Context())
			}))

			handler.ServeHTTP(rw, tt.req)

			if !reflect.DeepEqual(gotProvider, tt.want) {
				t.Errorf("provider matcher  = %v, want %v", gotProvider, tt.want)
			}

		})
	}
}
