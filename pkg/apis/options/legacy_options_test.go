package options

import (
	"encoding/base64"
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
			flushInterval := Duration(5 * time.Second)
			legacyOpts.LegacyUpstreams.FlushInterval = time.Duration(flushInterval)
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
					PreserveRequestValue: false,
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
					PreserveRequestValue: false,
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
					PreserveRequestValue: false,
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
					PreserveRequestValue: false,
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
		flushInterval := Duration(5 * time.Second)

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
					FlushInterval:                 time.Duration(flushInterval),
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

	Context("Legacy Headers", func() {
		const basicAuthSecret = "super-secret-password"

		type legacyHeadersTableInput struct {
			legacyHeaders           *LegacyHeaders
			expectedRequestHeaders  []Header
			expectedResponseHeaders []Header
		}

		withPreserveRequestValue := func(h Header, preserve bool) Header {
			h.PreserveRequestValue = preserve
			return h
		}

		xForwardedUser := Header{
			Name:                 "X-Forwarded-User",
			PreserveRequestValue: false,
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "user",
					},
				},
			},
		}

		xForwardedEmail := Header{
			Name:                 "X-Forwarded-Email",
			PreserveRequestValue: false,
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "email",
					},
				},
			},
		}

		xForwardedGroups := Header{
			Name:                 "X-Forwarded-Groups",
			PreserveRequestValue: false,
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "groups",
					},
				},
			},
		}

		xForwardedPreferredUsername := Header{
			Name:                 "X-Forwarded-Preferred-Username",
			PreserveRequestValue: false,
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "preferred_username",
					},
				},
			},
		}

		basicAuthHeader := Header{
			Name:                 "Authorization",
			PreserveRequestValue: false,
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "user",
						BasicAuthPassword: &SecretSource{
							Value: []byte(base64.StdEncoding.EncodeToString([]byte(basicAuthSecret))),
						},
					},
				},
			},
		}

		xForwardedUserWithEmail := Header{
			Name:                 "X-Forwarded-User",
			PreserveRequestValue: false,
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "email",
					},
				},
			},
		}

		xForwardedAccessToken := Header{
			Name:                 "X-Forwarded-Access-Token",
			PreserveRequestValue: false,
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "access_token",
					},
				},
			},
		}

		basicAuthHeaderWithEmail := Header{
			Name:                 "Authorization",
			PreserveRequestValue: false,
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "email",
						BasicAuthPassword: &SecretSource{
							Value: []byte(base64.StdEncoding.EncodeToString([]byte(basicAuthSecret))),
						},
					},
				},
			},
		}

		xAuthRequestUser := Header{
			Name:                 "X-Auth-Request-User",
			PreserveRequestValue: false,
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "user",
					},
				},
			},
		}

		xAuthRequestEmail := Header{
			Name:                 "X-Auth-Request-Email",
			PreserveRequestValue: false,
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "email",
					},
				},
			},
		}

		xAuthRequestGroups := Header{
			Name:                 "X-Auth-Request-Groups",
			PreserveRequestValue: false,
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "groups",
					},
				},
			},
		}

		xAuthRequestPreferredUsername := Header{
			Name:                 "X-Auth-Request-Preferred-Username",
			PreserveRequestValue: false,
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "preferred_username",
					},
				},
			},
		}

		xAuthRequestAccessToken := Header{
			Name:                 "X-Auth-Request-Access-Token",
			PreserveRequestValue: false,
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "access_token",
					},
				},
			},
		}

		authorizationHeader := Header{
			Name:                 "Authorization",
			PreserveRequestValue: false,
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim:  "id_token",
						Prefix: "Bearer ",
					},
				},
			},
		}

		DescribeTable("should convert to injectRequestHeaders",
			func(in legacyHeadersTableInput) {
				requestHeaders, responseHeaders := in.legacyHeaders.convert()
				Expect(requestHeaders).To(ConsistOf(in.expectedRequestHeaders))
				Expect(responseHeaders).To(ConsistOf(in.expectedResponseHeaders))
			},
			Entry("with all header options off", legacyHeadersTableInput{
				legacyHeaders: &LegacyHeaders{
					PassBasicAuth:     false,
					PassAccessToken:   false,
					PassUserHeaders:   false,
					PassAuthorization: false,

					SetBasicAuth:     false,
					SetXAuthRequest:  false,
					SetAuthorization: false,

					PreferEmailToUser:    false,
					BasicAuthPassword:    "",
					SkipAuthStripHeaders: true,
				},
				expectedRequestHeaders:  []Header{},
				expectedResponseHeaders: []Header{},
			}),
			Entry("with basic auth enabled", legacyHeadersTableInput{
				legacyHeaders: &LegacyHeaders{
					PassBasicAuth:     true,
					PassAccessToken:   false,
					PassUserHeaders:   false,
					PassAuthorization: false,

					SetBasicAuth:     true,
					SetXAuthRequest:  false,
					SetAuthorization: false,

					PreferEmailToUser:    false,
					BasicAuthPassword:    basicAuthSecret,
					SkipAuthStripHeaders: true,
				},
				expectedRequestHeaders: []Header{
					xForwardedUser,
					xForwardedEmail,
					xForwardedGroups,
					xForwardedPreferredUsername,
					basicAuthHeader,
				},
				expectedResponseHeaders: []Header{
					basicAuthHeader,
				},
			}),
			Entry("with basic auth enabled and skipAuthStripHeaders disabled", legacyHeadersTableInput{
				legacyHeaders: &LegacyHeaders{
					PassBasicAuth:     true,
					PassAccessToken:   false,
					PassUserHeaders:   false,
					PassAuthorization: false,

					SetBasicAuth:     true,
					SetXAuthRequest:  false,
					SetAuthorization: false,

					PreferEmailToUser:    false,
					BasicAuthPassword:    basicAuthSecret,
					SkipAuthStripHeaders: false,
				},
				expectedRequestHeaders: []Header{
					withPreserveRequestValue(xForwardedUser, true),
					withPreserveRequestValue(xForwardedEmail, true),
					withPreserveRequestValue(xForwardedGroups, true),
					withPreserveRequestValue(xForwardedPreferredUsername, true),
					withPreserveRequestValue(basicAuthHeader, true),
				},
				expectedResponseHeaders: []Header{
					basicAuthHeader,
				},
			}),
			Entry("with basic auth enabled and preferEmailToUser", legacyHeadersTableInput{
				legacyHeaders: &LegacyHeaders{
					PassBasicAuth:     true,
					PassAccessToken:   false,
					PassUserHeaders:   false,
					PassAuthorization: false,

					SetBasicAuth:     true,
					SetXAuthRequest:  false,
					SetAuthorization: false,

					PreferEmailToUser:    true,
					BasicAuthPassword:    basicAuthSecret,
					SkipAuthStripHeaders: true,
				},
				expectedRequestHeaders: []Header{
					xForwardedUserWithEmail,
					xForwardedGroups,
					xForwardedPreferredUsername,
					basicAuthHeaderWithEmail,
				},
				expectedResponseHeaders: []Header{
					basicAuthHeaderWithEmail,
				},
			}),
			Entry("with basic auth enabled and passUserHeaders", legacyHeadersTableInput{
				legacyHeaders: &LegacyHeaders{
					PassBasicAuth:     true,
					PassAccessToken:   false,
					PassUserHeaders:   true,
					PassAuthorization: false,

					SetBasicAuth:     true,
					SetXAuthRequest:  false,
					SetAuthorization: false,

					PreferEmailToUser:    false,
					BasicAuthPassword:    basicAuthSecret,
					SkipAuthStripHeaders: true,
				},
				expectedRequestHeaders: []Header{
					xForwardedUser,
					xForwardedEmail,
					xForwardedGroups,
					xForwardedPreferredUsername,
					basicAuthHeader,
				},
				expectedResponseHeaders: []Header{
					basicAuthHeader,
				},
			}),
			Entry("with passUserHeaders", legacyHeadersTableInput{
				legacyHeaders: &LegacyHeaders{
					PassBasicAuth:     false,
					PassAccessToken:   false,
					PassUserHeaders:   true,
					PassAuthorization: false,

					SetBasicAuth:     false,
					SetXAuthRequest:  false,
					SetAuthorization: false,

					PreferEmailToUser:    false,
					BasicAuthPassword:    "",
					SkipAuthStripHeaders: true,
				},
				expectedRequestHeaders: []Header{
					xForwardedUser,
					xForwardedEmail,
					xForwardedGroups,
					xForwardedPreferredUsername,
				},
				expectedResponseHeaders: []Header{},
			}),
			Entry("with passUserHeaders and SkipAuthStripHeaders disabled", legacyHeadersTableInput{
				legacyHeaders: &LegacyHeaders{
					PassBasicAuth:     false,
					PassAccessToken:   false,
					PassUserHeaders:   true,
					PassAuthorization: false,

					SetBasicAuth:     false,
					SetXAuthRequest:  false,
					SetAuthorization: false,

					PreferEmailToUser:    false,
					BasicAuthPassword:    "",
					SkipAuthStripHeaders: false,
				},
				expectedRequestHeaders: []Header{
					withPreserveRequestValue(xForwardedUser, true),
					withPreserveRequestValue(xForwardedEmail, true),
					withPreserveRequestValue(xForwardedGroups, true),
					withPreserveRequestValue(xForwardedPreferredUsername, true),
				},
				expectedResponseHeaders: []Header{},
			}),
			Entry("with setXAuthRequest", legacyHeadersTableInput{
				legacyHeaders: &LegacyHeaders{
					PassBasicAuth:     false,
					PassAccessToken:   false,
					PassUserHeaders:   false,
					PassAuthorization: false,

					SetBasicAuth:     false,
					SetXAuthRequest:  true,
					SetAuthorization: false,

					PreferEmailToUser:    false,
					BasicAuthPassword:    "",
					SkipAuthStripHeaders: true,
				},
				expectedRequestHeaders: []Header{},
				expectedResponseHeaders: []Header{
					xAuthRequestUser,
					xAuthRequestEmail,
					xAuthRequestGroups,
					xAuthRequestPreferredUsername,
				},
			}),
			Entry("with passAccessToken", legacyHeadersTableInput{
				legacyHeaders: &LegacyHeaders{
					PassBasicAuth:     false,
					PassAccessToken:   true,
					PassUserHeaders:   false,
					PassAuthorization: false,

					SetBasicAuth:     false,
					SetXAuthRequest:  false,
					SetAuthorization: false,

					PreferEmailToUser:    false,
					BasicAuthPassword:    "",
					SkipAuthStripHeaders: true,
				},
				expectedRequestHeaders: []Header{
					xForwardedAccessToken,
				},
				expectedResponseHeaders: []Header{},
			}),
			Entry("with passAcessToken and setXAuthRequest", legacyHeadersTableInput{
				legacyHeaders: &LegacyHeaders{
					PassBasicAuth:     false,
					PassAccessToken:   true,
					PassUserHeaders:   false,
					PassAuthorization: false,

					SetBasicAuth:     false,
					SetXAuthRequest:  true,
					SetAuthorization: false,

					PreferEmailToUser:    false,
					BasicAuthPassword:    "",
					SkipAuthStripHeaders: true,
				},
				expectedRequestHeaders: []Header{
					xForwardedAccessToken,
				},
				expectedResponseHeaders: []Header{
					xAuthRequestUser,
					xAuthRequestEmail,
					xAuthRequestGroups,
					xAuthRequestPreferredUsername,
					xAuthRequestAccessToken,
				},
			}),
			Entry("with passAcessToken and SkipAuthStripHeaders disabled", legacyHeadersTableInput{
				legacyHeaders: &LegacyHeaders{
					PassBasicAuth:     false,
					PassAccessToken:   true,
					PassUserHeaders:   false,
					PassAuthorization: false,

					SetBasicAuth:     false,
					SetXAuthRequest:  false,
					SetAuthorization: false,

					PreferEmailToUser:    false,
					BasicAuthPassword:    "",
					SkipAuthStripHeaders: false,
				},
				expectedRequestHeaders: []Header{
					withPreserveRequestValue(xForwardedAccessToken, true),
				},
				expectedResponseHeaders: []Header{},
			}),
			Entry("with authorization headers", legacyHeadersTableInput{
				legacyHeaders: &LegacyHeaders{
					PassBasicAuth:     false,
					PassAccessToken:   false,
					PassUserHeaders:   false,
					PassAuthorization: true,

					SetBasicAuth:     false,
					SetXAuthRequest:  false,
					SetAuthorization: true,

					PreferEmailToUser:    false,
					BasicAuthPassword:    "",
					SkipAuthStripHeaders: true,
				},
				expectedRequestHeaders: []Header{
					authorizationHeader,
				},
				expectedResponseHeaders: []Header{
					authorizationHeader,
				},
			}),
			Entry("with authorization headers and SkipAuthStripHeaders disabled", legacyHeadersTableInput{
				legacyHeaders: &LegacyHeaders{
					PassBasicAuth:     false,
					PassAccessToken:   false,
					PassUserHeaders:   false,
					PassAuthorization: true,

					SetBasicAuth:     false,
					SetXAuthRequest:  false,
					SetAuthorization: true,

					PreferEmailToUser:    false,
					BasicAuthPassword:    "",
					SkipAuthStripHeaders: false,
				},
				expectedRequestHeaders: []Header{
					withPreserveRequestValue(authorizationHeader, true),
				},
				expectedResponseHeaders: []Header{
					authorizationHeader,
				},
			}),
		)
	})
})
