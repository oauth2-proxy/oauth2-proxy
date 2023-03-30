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
				Rules: []*options.TenantMatcherRule{
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
				Rules: []*options.TenantMatcherRule{
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
				Rules: []*options.TenantMatcherRule{
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
