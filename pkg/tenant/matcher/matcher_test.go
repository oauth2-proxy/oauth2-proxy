package tenantmatcher

import (
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	tenantutils "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/tenant/utils"
)

func TestNew(t *testing.T) {
	reg, _ := regexp.Compile(".*")
	tests := []struct {
		name    string
		conf    options.TenantMatcher
		want    *Matcher
		wantErr bool
	}{
		{
			"new matcher",
			options.TenantMatcher{
				Rules: []options.TenantMatcherRule{
					{
						Source:       options.TenantMatcherRuleSourceQueryParams,
						QueryParam:   "tenantid",
						Expr:         ".*",
						CaptureGroup: 0,
					},
				},
			},
			&Matcher{
				rules: []*rule{{
					conf: &options.TenantMatcherRule{

						Source:       options.TenantMatcherRuleSourceQueryParams,
						QueryParam:   "tenantid",
						Expr:         ".*",
						CaptureGroup: 0,
					},
					regexp: reg,
				},
					{
						conf: &options.TenantMatcherRule{
							Source:       options.TenantMatcherRuleSourceQueryParams,
							QueryParam:   tenantutils.DefaultTenantIDQueryParam,
							Expr:         ".*",
							CaptureGroup: 0,
						},
						regexp: reg,
					},
				},
			},
			false,
		},
		{
			"new matcher -ve capture group",
			options.TenantMatcher{
				Rules: []options.TenantMatcherRule{
					{
						Source:       options.TenantMatcherRuleSourceQueryParams,
						QueryParam:   "tenantid",
						Expr:         ".*",
						CaptureGroup: -2,
					},
				},
			},
			nil,
			true,
		},
		{
			"new matcher invalid expression",
			options.TenantMatcher{
				Rules: []options.TenantMatcherRule{
					{
						Source:       options.TenantMatcherRuleSourceQueryParams,
						QueryParam:   "tenantid",
						Expr:         `^\/(?!\/)(.*?)`,
						CaptureGroup: 0,
					},
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
				t.Errorf("New matcher = %v, want %v", got, tt.want)
			} else if err != nil && !tt.wantErr {
				t.Errorf("New matcher, got error: '%v'", err)
			}
		})
	}
}

func TestMatch(t *testing.T) {
	reg, _ := regexp.Compile(".*")
	reg2, _ := regexp.Compile(`Bearer\s+([^\s]+)`)
	tests := []struct {
		name    string
		matcher *Matcher
		req     *http.Request
		want    string
	}{
		{
			"Match with tenantid in req host",
			&Matcher{
				rules: []*rule{
					{
						conf: &options.TenantMatcherRule{
							Source:       options.TenantMatcherRuleSourceHost,
							Expr:         ".*",
							CaptureGroup: 0,
						},
						regexp: reg,
					},
				},
			},
			&http.Request{
				Host: "id",
			},
			"id",
		},
		{
			"Match with tenantid in jwt token",
			&Matcher{
				rules: []*rule{

					{
						conf: &options.TenantMatcherRule{
							Source:   options.TenantMatcherRuleSourceHeader,
							Expr:     `Bearer\s+([^\s]+)`,
							Header:   "Authorization",
							JWTClaim: "tenant.id",
						},
						regexp: reg2,
					},
				},
			},
			&http.Request{
				Header: http.Header{
					"Authorization": {"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJ0ZW5hbnQiOnsiaWQiOiJ0ZW5hbnQxIn19.e5rSX1K4KNzIylFoN43hTQcwrsrt-GvDHsK3SSfTPHc"},
				},
			},
			"tenant1",
		},
		{
			"Match with tenantid in req path",
			&Matcher{
				rules: []*rule{

					{
						conf: &options.TenantMatcherRule{
							Source:       options.TenantMatcherRuleSourcePath,
							Expr:         ".*",
							CaptureGroup: 0,
						},
						regexp: reg,
					},
				},
			},
			&http.Request{
				Host: "id",
				URL: &url.URL{
					Path: "tenant",
				},
			},
			"tenant",
		},
		{
			"Match with tenantid in header",
			&Matcher{
				rules: []*rule{

					{
						conf: &options.TenantMatcherRule{
							Source:       options.TenantMatcherRuleSourceHeader,
							Expr:         ".*",
							CaptureGroup: 0,
							Header:       "Tenantid",
						},
						regexp: reg,
					},
				},
			},
			&http.Request{
				Header: http.Header{
					"Tenantid": {"dummytenant"},
				},
			},
			"dummytenant",
		},
		{
			"Match with tenantid in query param",
			&Matcher{
				rules: []*rule{

					{
						conf: &options.TenantMatcherRule{
							Source:       options.TenantMatcherRuleSourceQueryParams,
							Expr:         ".*",
							CaptureGroup: 0,
							QueryParam:   "tenantid",
						},
						regexp: reg,
					},
				},
			},
			&http.Request{
				URL: &url.URL{
					RawQuery: url.Values{
						"tenantid": {"id"},
					}.Encode(),
				},
			},
			"id",
		},
		{
			"Match with tenantid not found",
			&Matcher{
				rules: []*rule{

					{
						conf: &options.TenantMatcherRule{
							Source:       options.TenantMatcherRuleSourceQueryParams,
							Expr:         ".*",
							CaptureGroup: 0,
							QueryParam:   "tenantid",
						},
						regexp: reg,
					},
				},
			},
			&http.Request{
				URL: &url.URL{},
			},
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.matcher.Match(tt.req)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Match returned id = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_exractTenantIDFromJWT(t *testing.T) {
	tests := []struct {
		name  string
		jwt   string
		claim string
		want  string
	}{
		{
			"no tenant-id found due to invalid token",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0",
			"",
			"",
		},
		{
			"no tenant-id found due to invalid base64 encoding of jwt token payload",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJ0ZW5hbnQiOnsiaWQiOiJ0ZW5%hbnQxIn19.e5rSX1K4KNzIylFoN43hTQcwrsrt-GvDHsK3SSfTPHc",
			"",
			"",
		},
		{
			"no error tenant-id found",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJ0ZW5hbnQiOnsiaWQiOiJ0ZW5hbnQxIn19.e5rSX1K4KNzIylFoN43hTQcwrsrt-GvDHsK3SSfTPHc",
			"tenant.id",
			"tenant1",
		},
		{
			"no tenant-id found due to invalid claim",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJ0ZW5hbnQiOnsiaWQiOiJ0ZW5hbnQxIn19.e5rSX1K4KNzIylFoN43hTQcwrsrt-GvDHsK3SSfTPHc",
			"t.id",
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := exractTenantIDFromJWT(tt.jwt, tt.claim)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extract tenant ID from JWT = %v, want %v", got, tt.want)
			}
		})
	}
}
