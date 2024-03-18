package matcher

import (
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers/utils"
)

func TestNew(t *testing.T) {
	reg, _ := regexp.Compile(".*")
	tests := []struct {
		name    string
		conf    options.ProviderMatcher
		want    *Matcher
		wantErr bool
	}{
		{
			"new matcher",
			options.ProviderMatcher{
				Rules: []options.ProviderMatcherRule{
					{
						Source:       options.ProviderMatcherRuleSourceQueryParams,
						QueryParam:   "providerid",
						Expr:         ".*",
						CaptureGroup: 0,
					},
				},
			},
			&Matcher{
				rules: []*rule{{
					conf: &options.ProviderMatcherRule{

						Source:       options.ProviderMatcherRuleSourceQueryParams,
						QueryParam:   "providerid",
						Expr:         ".*",
						CaptureGroup: 0,
					},
					regexp: reg,
				},
					{
						conf: &options.ProviderMatcherRule{
							Source:       options.ProviderMatcherRuleSourceQueryParams,
							QueryParam:   utils.DefaultProviderIDQueryParam,
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
			options.ProviderMatcher{
				Rules: []options.ProviderMatcherRule{
					{
						Source:       options.ProviderMatcherRuleSourceQueryParams,
						QueryParam:   "providerid",
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
			options.ProviderMatcher{
				Rules: []options.ProviderMatcherRule{
					{
						Source:       options.ProviderMatcherRuleSourceQueryParams,
						QueryParam:   "providerid",
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
			"Match with providerid in req host",
			&Matcher{
				rules: []*rule{
					{
						conf: &options.ProviderMatcherRule{
							Source:       options.ProviderMatcherRuleSourceHost,
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
			"Match with providerid in jwt token",
			&Matcher{
				rules: []*rule{

					{
						conf: &options.ProviderMatcherRule{
							Source:   options.ProviderMatcherRuleSourceHeader,
							Expr:     `Bearer\s+([^\s]+)`,
							Header:   "Authorization",
							JWTClaim: "provider.id",
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
			"provider1",
		},
		{
			"Match with providerid in req path",
			&Matcher{
				rules: []*rule{

					{
						conf: &options.ProviderMatcherRule{
							Source:       options.ProviderMatcherRuleSourcePath,
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
					Path: "provider",
				},
			},
			"provider",
		},
		{
			"Match with providerid in header",
			&Matcher{
				rules: []*rule{

					{
						conf: &options.ProviderMatcherRule{
							Source:       options.ProviderMatcherRuleSourceHeader,
							Expr:         ".*",
							CaptureGroup: 0,
							Header:       "Providerid",
						},
						regexp: reg,
					},
				},
			},
			&http.Request{
				Header: http.Header{
					"Providerid": {"dummyprovider"},
				},
			},
			"dummyprovider",
		},
		{
			"Match with providerid in query param",
			&Matcher{
				rules: []*rule{

					{
						conf: &options.ProviderMatcherRule{
							Source:       options.ProviderMatcherRuleSourceQueryParams,
							Expr:         ".*",
							CaptureGroup: 0,
							QueryParam:   "providerid",
						},
						regexp: reg,
					},
				},
			},
			&http.Request{
				URL: &url.URL{
					RawQuery: url.Values{
						"providerid": {"id"},
					}.Encode(),
				},
			},
			"id",
		},
		{
			"Match with providerid not found",
			&Matcher{
				rules: []*rule{

					{
						conf: &options.ProviderMatcherRule{
							Source:       options.ProviderMatcherRuleSourceQueryParams,
							Expr:         ".*",
							CaptureGroup: 0,
							QueryParam:   "providerid",
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

func Test_exractProviderIDFromJWT(t *testing.T) {
	tests := []struct {
		name  string
		jwt   string
		claim string
		want  string
	}{
		{
			"no provider-id found due to invalid token",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0",
			"",
			"",
		},
		{
			"no provider-id found due to invalid base64 encoding of jwt token payload",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJ0ZW5hbnQiOnsiaWQiOiJ0ZW5%hbnQxIn19.e5rSX1K4KNzIylFoN43hTQcwrsrt-GvDHsK3SSfTPHc",
			"",
			"",
		},
		{
			"no error provider-id found",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJ0ZW5hbnQiOnsiaWQiOiJ0ZW5hbnQxIn19.e5rSX1K4KNzIylFoN43hTQcwrsrt-GvDHsK3SSfTPHc",
			"provider.id",
			"provider1",
		},
		{
			"no provider-id found due to invalid claim",
			"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJ0ZW5hbnQiOnsiaWQiOiJ0ZW5hbnQxIn19.e5rSX1K4KNzIylFoN43hTQcwrsrt-GvDHsK3SSfTPHc",
			"t.id",
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := exractProviderIDFromJWT(tt.jwt, tt.claim)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extract provider ID from JWT = %v, want %v", got, tt.want)
			}
		})
	}
}
