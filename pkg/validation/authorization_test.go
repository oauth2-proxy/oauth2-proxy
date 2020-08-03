package validation

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/authorization"
	"github.com/stretchr/testify/assert"
)

func Test_validateAuthorization(t *testing.T) {
	opts := &options.Options{
		Authorization: options.LegacyAuthorization{
			SkipAuthRoutes: []string{
				"POST=/foo/bar",
				"PUT=^/foo/bar$",
			},
			SkipAuthRegex:     []string{"/foo/baz"},
			SkipAuthPreflight: true,
			TrustedIPs: []string{
				"10.32.0.1/32",
				"43.36.201.0/24",
			},
		},
	}
	assert.Equal(t, []string{}, validateAuthorization(opts))

	re := opts.Authorization.GetRulesEngine()
	// Trusted via SkipAuthRoutes
	routeReq := &http.Request{
		Method: "POST",
		URL: &url.URL{
			Path: "/foo/bar",
		},
		RemoteAddr: "1.2.3.4:443",
	}
	assert.Equal(t, authorization.AllowPolicy, re.Match(routeReq, nil))

	// Trusted via SkipAuthRegex
	regexReq := &http.Request{
		Method: "GET",
		URL: &url.URL{
			Path: "/foo/baz",
		},
		RemoteAddr: "1.2.3.4:443",
	}
	assert.Equal(t, authorization.AllowPolicy, re.Match(regexReq, nil))

	// Trusted via SkipAuthPreflight
	preflightReq := &http.Request{
		Method: "OPTIONS",
		URL: &url.URL{
			Path: "/any/path/works",
		},
		RemoteAddr: "1.2.3.4:443",
	}
	assert.Equal(t, authorization.AllowPolicy, re.Match(preflightReq, nil))

	// Trusted via TrustedIPs
	ipReq := &http.Request{
		Method: "POST",
		URL: &url.URL{
			Path: "/super/secret/route",
		},
		RemoteAddr: "10.32.0.1:443",
	}
	assert.Equal(t, authorization.AllowPolicy, re.Match(ipReq, nil))

	// Not trusted
	authReq := &http.Request{
		Method: "POST",
		URL: &url.URL{
			Path: "/super/secret/route",
		},
		RemoteAddr: "1.2.3.4:443",
	}
	assert.Equal(t, authorization.AuthPolicy, re.Match(authReq, nil))
}

func Test_validateRoutes(t *testing.T) {
	testCases := map[string]struct {
		Regexes  []string
		Expected []string
	}{
		"Non-overlapping regex routes": {
			Regexes: []string{
				"/foo",
				"POST=/foo/bar",
				"PUT=^/foo/bar$",
				"DELETE=/crazy/(?:regex)?/[^/]+/stuff$",
			},
			Expected: []string{},
		},
		"Overlapping regex routes removes duplicates": {
			Regexes: []string{
				"GET=/foo",
				"POST=/foo/bar",
				"^/foo/bar$",
				"/crazy/(?:regex)?/[^/]+/stuff$",
				"GET=/foo",
			},
			Expected: []string{},
		},
		"Bad regexes do not compile": {
			Regexes: []string{
				"POST=/(foo",
				"OPTIONS=/foo/bar)",
				"GET=^]/foo/bar[$",
				"GET=^]/foo/bar[$",
			},
			Expected: []string{
				"error compiling regex //(foo/: error parsing regexp: missing closing ): `/(foo`",
				"error compiling regex //foo/bar)/: error parsing regexp: unexpected ): `/foo/bar)`",
				"error compiling regex /^]/foo/bar[$/: error parsing regexp: missing closing ]: `[$`",
				"error compiling regex /^]/foo/bar[$/: error parsing regexp: missing closing ]: `[$`",
			},
		},
	}

	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			re := authorization.NewRulesEngine(authorization.AuthPolicy)
			opts := &options.LegacyAuthorization{
				SkipAuthRoutes: tc.Regexes,
			}
			msgs := validateRoutes(opts, re)
			assert.Equal(t, tc.Expected, msgs)
			// Confirm validator populated the authorization.Routes
			if len(msgs) == 0 {
				req := &http.Request{
					Method: "GET",
					URL: &url.URL{
						Path: "/foo",
					},
				}
				assert.Equal(t, authorization.AllowPolicy, re.Match(req, nil))
				req.URL.Path = "/wrong"
				assert.Equal(t, authorization.AuthPolicy, re.Match(req, nil))
			}
		})
	}
}

func Test_validateRegexes(t *testing.T) {
	testCases := map[string]struct {
		Regexes  []string
		Expected []string
	}{
		"Non-overlapping regex routes": {
			Regexes: []string{
				"/foo",
				"/foo/bar",
				"^/foo/bar$",
				"/crazy/(?:regex)?/[^/]+/stuff$",
			},
			Expected: []string{},
		},
		"Overlapping regex routes removes duplicates": {
			Regexes: []string{
				"/foo",
				"/foo/bar",
				"^/foo/bar$",
				"/crazy/(?:regex)?/[^/]+/stuff$",
				"^/foo/bar$",
			},
			Expected: []string{},
		},
		"Bad regexes do not compile": {
			Regexes: []string{
				"/(foo",
				"/foo/bar)",
				"^]/foo/bar[$",
				"^]/foo/bar[$",
			},
			Expected: []string{
				"error compiling regex //(foo/: error parsing regexp: missing closing ): `/(foo`",
				"error compiling regex //foo/bar)/: error parsing regexp: unexpected ): `/foo/bar)`",
				"error compiling regex /^]/foo/bar[$/: error parsing regexp: missing closing ]: `[$`",
				"error compiling regex /^]/foo/bar[$/: error parsing regexp: missing closing ]: `[$`",
			},
		},
	}

	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			re := authorization.NewRulesEngine(authorization.AuthPolicy)
			opts := &options.LegacyAuthorization{
				SkipAuthRegex: tc.Regexes,
			}
			msgs := validateRegexes(opts, re)
			assert.Equal(t, tc.Expected, msgs)
			// Confirm validator populated the authorization.Routes
			if len(msgs) == 0 {
				req := &http.Request{
					URL: &url.URL{
						Path: "/foo",
					},
				}
				assert.Equal(t, authorization.AllowPolicy, re.Match(req, nil))
				req.URL.Path = "/wrong"
				assert.Equal(t, authorization.AuthPolicy, re.Match(req, nil))
			}
		})
	}
}

func Test_validatePreflight(t *testing.T) {
	for _, skipped := range []bool{true, false} {
		t.Run(fmt.Sprintf("%t", skipped), func(t *testing.T) {
			re := authorization.NewRulesEngine(authorization.AuthPolicy)
			opts := &options.LegacyAuthorization{
				SkipAuthPreflight: skipped,
			}
			msgs := validatePreflight(opts, re)
			assert.Equal(t, msgs, []string{})

			optionsReq := &http.Request{
				Method: "OPTIONS",
				URL: &url.URL{
					Path: "/any/path/works",
				},
			}
			assert.Equal(t, skipped, re.Match(optionsReq, nil) == authorization.AllowPolicy)

			getReq := &http.Request{
				Method: "GET",
				URL: &url.URL{
					Path: "/any/path/works",
				},
			}
			assert.Equal(t, authorization.AuthPolicy, re.Match(getReq, nil))
		})
	}
}

func Test_validateTrustedIPs(t *testing.T) {
	testCases := map[string]struct {
		TrustedIPs []string
		RequestIP  string
		Expected   []string
	}{
		"Non-overlapping valid IPs": {
			TrustedIPs: []string{
				"127.0.0.1",
				"10.32.0.1/32",
				"43.36.201.0/24",
				"::1",
				"2a12:105:ee7:9234:0:0:0:0/64",
			},
			RequestIP: "43.36.201.100",
			Expected:  []string{},
		},
		"Overlapping valid IPs": {
			TrustedIPs: []string{
				"135.180.78.199",
				"135.180.78.199/32",
				"d910:a5a1:16f8:ddf5:e5b9:5cef:a65e:41f4",
				"d910:a5a1:16f8:ddf5:e5b9:5cef:a65e:41f4/128",
			},
			RequestIP: "135.180.78.199",
			Expected:  []string{},
		},
		"Invalid IPs": {
			TrustedIPs: []string{"[::1]", "alkwlkbn/32"},
			Expected: []string{
				"could not parse trusted IP network(s): [::1], alkwlkbn/32",
			},
		},
	}

	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			re := authorization.NewRulesEngine(authorization.AuthPolicy)
			opts := &options.LegacyAuthorization{
				TrustedIPs: tc.TrustedIPs,
			}
			msgs := validateTrustedIPs(opts, re, nil)
			assert.Equal(t, tc.Expected, msgs)
			// Confirm validator populated the authorization.IPs
			if len(msgs) == 0 {
				req := &http.Request{
					RemoteAddr: fmt.Sprintf("%s:443", tc.RequestIP),
				}
				assert.Equal(t, authorization.AllowPolicy, re.Match(req, nil))
			}
		})
	}
}
