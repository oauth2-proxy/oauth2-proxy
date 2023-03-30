package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	tenantmatcher "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/tenant/matcher"
	tenantutils "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/tenant/utils"
)

func TestTenantMatcher(t *testing.T) {

	rw := httptest.NewRecorder()
	tm, _ := tenantmatcher.New(options.TenantMatcher{
		Rules: []*options.TenantMatcherRule{
			{
				Source:       options.TenantMatcherRuleSourceQueryParams,
				QueryParam:   "tenantid",
				Expr:         ".*",
				CaptureGroup: 0,
			},
			{

				Source:       options.TenantMatcherRuleSourceHost,
				Expr:         ".*",
				CaptureGroup: 0,
			},
			{
				Source:       options.TenantMatcherRuleSourcePath,
				Expr:         ".*",
				CaptureGroup: 0,
			},
			{
				Source:       options.TenantMatcherRuleSourceHeader,
				Expr:         ".*",
				CaptureGroup: 0,
				Header:       "Tenantid",
			},
		},
	})

	tests := []struct {
		name string
		want string
		req  *http.Request
	}{
		{"tenant matcher query",
			"id",
			&http.Request{
				URL: &url.URL{
					RawQuery: url.Values{
						"tenantid": {"id"},
					}.Encode(),
				},
			},
		},
		{
			"tenant matcher host",
			"dummy",
			&http.Request{
				Host: "dummy",
				URL:  &url.URL{},
			},
		},
		{
			"tenant matcher path",
			"tenant",
			&http.Request{
				URL: &url.URL{
					Path: "tenant",
				},
			},
		},
		{
			"tenant matcher header",
			"dummytenant",
			&http.Request{
				URL: &url.URL{},
				Header: http.Header{
					"Tenantid": {"dummytenant"},
				},
			},
		},
	}

	for _, tt := range tests {
		var gotTenant string
		t.Run(tt.name, func(t *testing.T) {
			handler := NewTenantMatcher(tm)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

				gotTenant = tenantutils.FromContext(r.Context())
			}))

			handler.ServeHTTP(rw, tt.req)

			if !reflect.DeepEqual(gotTenant, tt.want) {
				t.Errorf("tenant matcher  = %v, want %v", gotTenant, tt.want)
			}

		})
	}
}
