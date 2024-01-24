package validation

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
)

var _ = Describe("Allowlist", func() {
	type validateRoutesTableInput struct {
		routes     []string
		errStrings []string
	}

	type validateRegexesTableInput struct {
		regexes    []string
		errStrings []string
	}

	type validateTrustedIPsTableInput struct {
		trustedIPs []string
		errStrings []string
	}

	DescribeTable("validateRoutes",
		func(r *validateRoutesTableInput) {
			opts := &options.Options{
				SkipAuthRoutes: r.routes,
			}
			Expect(validateAuthRoutes(opts)).To(ConsistOf(r.errStrings))
		},
		Entry("Valid regex routes", &validateRoutesTableInput{
			routes: []string{
				"/foo",
				"POST=/foo/bar",
				"PUT=^/foo/bar$",
				"DELETE=/crazy/(?:regex)?/[^/]+/stuff$",
			},
			errStrings: []string{},
		}),
		Entry("Bad regexes do not compile", &validateRoutesTableInput{
			routes: []string{
				"POST=/(foo",
				"OPTIONS=/foo/bar)",
				"GET=^]/foo/bar[$",
				"GET=^]/foo/bar[$",
			},
			errStrings: []string{
				"error compiling regex //(foo/: error parsing regexp: missing closing ): `/(foo`",
				"error compiling regex //foo/bar)/: error parsing regexp: unexpected ): `/foo/bar)`",
				"error compiling regex /^]/foo/bar[$/: error parsing regexp: missing closing ]: `[$`",
				"error compiling regex /^]/foo/bar[$/: error parsing regexp: missing closing ]: `[$`",
			},
		}),
	)

	DescribeTable("validateRegexes",
		func(r *validateRegexesTableInput) {
			opts := &options.Options{
				SkipAuthRegex: r.regexes,
			}
			Expect(validateAuthRegexes(opts)).To(ConsistOf(r.errStrings))
		},
		Entry("Valid regex routes", &validateRegexesTableInput{
			regexes: []string{
				"/foo",
				"/foo/bar",
				"^/foo/bar$",
				"/crazy/(?:regex)?/[^/]+/stuff$",
			},
			errStrings: []string{},
		}),
		Entry("Bad regexes do not compile", &validateRegexesTableInput{
			regexes: []string{
				"/(foo",
				"/foo/bar)",
				"^]/foo/bar[$",
				"^]/foo/bar[$",
			},
			errStrings: []string{
				"error compiling regex //(foo/: error parsing regexp: missing closing ): `/(foo`",
				"error compiling regex //foo/bar)/: error parsing regexp: unexpected ): `/foo/bar)`",
				"error compiling regex /^]/foo/bar[$/: error parsing regexp: missing closing ]: `[$`",
				"error compiling regex /^]/foo/bar[$/: error parsing regexp: missing closing ]: `[$`",
			},
		}),
	)

	DescribeTable("validateTrustedIPs",
		func(t *validateTrustedIPsTableInput) {
			opts := &options.Options{
				TrustedIPs: t.trustedIPs,
			}
			Expect(validateTrustedIPs(opts)).To(ConsistOf(t.errStrings))
		},
		Entry("Non-overlapping valid IPs", &validateTrustedIPsTableInput{
			trustedIPs: []string{
				"127.0.0.1",
				"10.32.0.1/32",
				"43.36.201.0/24",
				"::1",
				"2a12:105:ee7:9234:0:0:0:0/64",
			},
			errStrings: []string{},
		}),
		Entry("Overlapping valid IPs", &validateTrustedIPsTableInput{
			trustedIPs: []string{
				"135.180.78.199",
				"135.180.78.199/32",
				"d910:a5a1:16f8:ddf5:e5b9:5cef:a65e:41f4",
				"d910:a5a1:16f8:ddf5:e5b9:5cef:a65e:41f4/128",
			},
			errStrings: []string{},
		}),
		Entry("Invalid IPs", &validateTrustedIPsTableInput{
			trustedIPs: []string{"[::1]", "alkwlkbn/32"},
			errStrings: []string{
				"trusted_ips[0] ([::1]) could not be recognized",
				"trusted_ips[1] (alkwlkbn/32) could not be recognized",
			},
		}),
	)
})
