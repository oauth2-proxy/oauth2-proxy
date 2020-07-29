package options

import (
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("Legacy Options", func() {
	Context("ToOptions", func() {
		It("converts the options as expected", func() {
			opts := NewOptions()

			legacyOpts := NewLegacyOptions()

			// Set upstreams and related options to test their conversion
			flushInterval := 5 * time.Second
			legacyOpts.LegacyUpstreams.FlushInterval = flushInterval
			legacyOpts.LegacyUpstreams.PassHostHeader = true
			legacyOpts.LegacyUpstreams.ProxyWebSockets = true
			legacyOpts.LegacyUpstreams.SSLUpstreamInsecureSkipVerify = true
			legacyOpts.LegacyUpstreams.Upstreams = []string{"http://foo.bar/baz", "file:///var/lib/website#/bar", "static://204"}

			truth := true
			staticCode := 204
			opts.UpstreamServers = Upstreams{
				{
					ID:                    "/baz",
					Path:                  "/baz",
					URI:                   "http://foo.bar/baz",
					FlushInterval:         &flushInterval,
					InsecureSkipTLSVerify: true,
					PassHostHeader:        &truth,
					ProxyWebSockets:       &truth,
				},
				{
					ID:                    "/bar",
					Path:                  "/bar",
					URI:                   "file:///var/lib/website",
					FlushInterval:         &flushInterval,
					InsecureSkipTLSVerify: true,
					PassHostHeader:        &truth,
					ProxyWebSockets:       &truth,
				},
				{
					ID:                    "static://204",
					Path:                  "/",
					URI:                   "",
					Static:                true,
					StaticCode:            &staticCode,
					FlushInterval:         nil,
					InsecureSkipTLSVerify: false,
					PassHostHeader:        nil,
					ProxyWebSockets:       nil,
				},
			}

			opts.InjectRequestHeaders = []Header{
				{
					Name:                 "X-Forwarded-Groups",
					PreserveRequestValue: true,
					Values: []HeaderValue{
						{
							ClaimSource: &ClaimSource{
								Claim: "groups",
							},
						},
					},
				},
				{
					Name:                 "X-Forwarded-User",
					PreserveRequestValue: true,
					Values: []HeaderValue{
						{
							ClaimSource: &ClaimSource{
								Claim: "user",
							},
						},
					},
				},
				{
					Name:                 "X-Forwarded-Email",
					PreserveRequestValue: true,
					Values: []HeaderValue{
						{
							ClaimSource: &ClaimSource{
								Claim: "email",
							},
						},
					},
				},
				{
					Name:                 "X-Forwarded-Preferred-Username",
					PreserveRequestValue: true,
					Values: []HeaderValue{
						{
							ClaimSource: &ClaimSource{
								Claim: "preferred_username",
							},
						},
					},
				},
			}

			opts.InjectResponseHeaders = []Header{}

			converted, err := legacyOpts.ToOptions()
			Expect(err).ToNot(HaveOccurred())
			Expect(converted).To(Equal(opts))
		})
	})

	Context("Legacy Upstreams", func() {
		type convertUpstreamsTableInput struct {
			upstreamStrings   []string
			expectedUpstreams Upstreams
			errMsg            string
		}

		// Non defaults for these options
		skipVerify := true
		passHostHeader := false
		proxyWebSockets := true
		flushInterval := 5 * time.Second

		// Test cases and expected outcomes
		validHTTP := "http://foo.bar/baz"
		validHTTPUpstream := Upstream{
			ID:                    "/baz",
			Path:                  "/baz",
			URI:                   validHTTP,
			InsecureSkipTLSVerify: skipVerify,
			PassHostHeader:        &passHostHeader,
			ProxyWebSockets:       &proxyWebSockets,
			FlushInterval:         &flushInterval,
		}

		// Test cases and expected outcomes
		emptyPathHTTP := "http://foo.bar"
		emptyPathHTTPUpstream := Upstream{
			ID:                    "/",
			Path:                  "/",
			URI:                   emptyPathHTTP,
			InsecureSkipTLSVerify: skipVerify,
			PassHostHeader:        &passHostHeader,
			ProxyWebSockets:       &proxyWebSockets,
			FlushInterval:         &flushInterval,
		}

		validFileWithFragment := "file:///var/lib/website#/bar"
		validFileWithFragmentUpstream := Upstream{
			ID:                    "/bar",
			Path:                  "/bar",
			URI:                   "file:///var/lib/website",
			InsecureSkipTLSVerify: skipVerify,
			PassHostHeader:        &passHostHeader,
			ProxyWebSockets:       &proxyWebSockets,
			FlushInterval:         &flushInterval,
		}

		validStatic := "static://204"
		validStaticCode := 204
		validStaticUpstream := Upstream{
			ID:                    validStatic,
			Path:                  "/",
			URI:                   "",
			Static:                true,
			StaticCode:            &validStaticCode,
			InsecureSkipTLSVerify: false,
			PassHostHeader:        nil,
			ProxyWebSockets:       nil,
			FlushInterval:         nil,
		}

		invalidStatic := "static://abc"
		invalidStaticCode := 200
		invalidStaticUpstream := Upstream{
			ID:                    invalidStatic,
			Path:                  "/",
			URI:                   "",
			Static:                true,
			StaticCode:            &invalidStaticCode,
			InsecureSkipTLSVerify: false,
			PassHostHeader:        nil,
			ProxyWebSockets:       nil,
			FlushInterval:         nil,
		}

		invalidHTTP := ":foo"
		invalidHTTPErrMsg := "could not parse upstream \":foo\": parse \":foo\": missing protocol scheme"

		DescribeTable("convertLegacyUpstreams",
			func(o *convertUpstreamsTableInput) {
				legacyUpstreams := LegacyUpstreams{
					Upstreams:                     o.upstreamStrings,
					SSLUpstreamInsecureSkipVerify: skipVerify,
					PassHostHeader:                passHostHeader,
					ProxyWebSockets:               proxyWebSockets,
					FlushInterval:                 flushInterval,
				}

				upstreams, err := legacyUpstreams.convert()

				if o.errMsg != "" {
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(Equal(o.errMsg))
				} else {
					Expect(err).ToNot(HaveOccurred())
				}

				Expect(upstreams).To(ConsistOf(o.expectedUpstreams))
			},
			Entry("with no upstreams", &convertUpstreamsTableInput{
				upstreamStrings:   []string{},
				expectedUpstreams: Upstreams{},
				errMsg:            "",
			}),
			Entry("with a valid HTTP upstream", &convertUpstreamsTableInput{
				upstreamStrings:   []string{validHTTP},
				expectedUpstreams: Upstreams{validHTTPUpstream},
				errMsg:            "",
			}),
			Entry("with a HTTP upstream with an empty path", &convertUpstreamsTableInput{
				upstreamStrings:   []string{emptyPathHTTP},
				expectedUpstreams: Upstreams{emptyPathHTTPUpstream},
				errMsg:            "",
			}),
			Entry("with a valid File upstream with a fragment", &convertUpstreamsTableInput{
				upstreamStrings:   []string{validFileWithFragment},
				expectedUpstreams: Upstreams{validFileWithFragmentUpstream},
				errMsg:            "",
			}),
			Entry("with a valid static upstream", &convertUpstreamsTableInput{
				upstreamStrings:   []string{validStatic},
				expectedUpstreams: Upstreams{validStaticUpstream},
				errMsg:            "",
			}),
			Entry("with an invalid static upstream, code is 200", &convertUpstreamsTableInput{
				upstreamStrings:   []string{invalidStatic},
				expectedUpstreams: Upstreams{invalidStaticUpstream},
				errMsg:            "",
			}),
			Entry("with an invalid HTTP upstream", &convertUpstreamsTableInput{
				upstreamStrings:   []string{invalidHTTP},
				expectedUpstreams: Upstreams{},
				errMsg:            invalidHTTPErrMsg,
			}),
			Entry("with an invalid HTTP upstream and other upstreams", &convertUpstreamsTableInput{
				upstreamStrings:   []string{validHTTP, invalidHTTP},
				expectedUpstreams: Upstreams{},
				errMsg:            invalidHTTPErrMsg,
			}),
			Entry("with multiple valid upstreams", &convertUpstreamsTableInput{
				upstreamStrings:   []string{validHTTP, validFileWithFragment, validStatic},
				expectedUpstreams: Upstreams{validHTTPUpstream, validFileWithFragmentUpstream, validStaticUpstream},
				errMsg:            "",
			}),
		)
	})
})
