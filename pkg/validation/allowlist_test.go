package validation

import (
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/options"
	"github.com/stretchr/testify/assert"
)

func Test_validateAllowlists(t *testing.T) {
	opts := &options.Options{
		SkipAuthRoutes: []string{
			"POST=/foo/bar",
			"PUT=^/foo/bar$",
		},
		SkipAuthRegex: []string{"/foo/baz"},
		TrustedIPs: []string{
			"10.32.0.1/32",
			"43.36.201.0/24",
		},
	}
	assert.Equal(t, []string{}, validateAllowlists(opts))
}

func Test_validateRoutes(t *testing.T) {
	testCases := map[string]struct {
		Regexes  []string
		Expected []string
	}{
		"Valid regex routes": {
			Regexes: []string{
				"/foo",
				"POST=/foo/bar",
				"PUT=^/foo/bar$",
				"DELETE=/crazy/(?:regex)?/[^/]+/stuff$",
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
			opts := &options.Options{
				SkipAuthRoutes: tc.Regexes,
			}
			msgs := validateRoutes(opts)
			assert.Equal(t, tc.Expected, msgs)
		})
	}
}

func Test_validateRegexes(t *testing.T) {
	testCases := map[string]struct {
		Regexes  []string
		Expected []string
	}{
		"Valid regex routes": {
			Regexes: []string{
				"/foo",
				"/foo/bar",
				"^/foo/bar$",
				"/crazy/(?:regex)?/[^/]+/stuff$",
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
			opts := &options.Options{
				SkipAuthRegex: tc.Regexes,
			}
			msgs := validateRegexes(opts)
			assert.Equal(t, tc.Expected, msgs)
		})
	}
}

func Test_validateTrustedIPs(t *testing.T) {
	testCases := map[string]struct {
		TrustedIPs []string
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
			Expected: []string{},
		},
		"Overlapping valid IPs": {
			TrustedIPs: []string{
				"135.180.78.199",
				"135.180.78.199/32",
				"d910:a5a1:16f8:ddf5:e5b9:5cef:a65e:41f4",
				"d910:a5a1:16f8:ddf5:e5b9:5cef:a65e:41f4/128",
			},
			Expected: []string{},
		},
		"Invalid IPs": {
			TrustedIPs: []string{"[::1]", "alkwlkbn/32"},
			Expected: []string{
				"trusted_ips[0] ([::1]) could not be recognized",
				"trusted_ips[1] (alkwlkbn/32) could not be recognized",
			},
		},
	}

	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			opts := &options.Options{
				TrustedIPs: tc.TrustedIPs,
			}
			msgs := validateTrustedIPs(opts)
			assert.Equal(t, tc.Expected, msgs)
		})
	}
}
