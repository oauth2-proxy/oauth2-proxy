package options

import (
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Legacy Options", func() {
	Context("ToOptions", func() {
		It("converts the options as expected", func() {
			opts := NewOptions()

			legacyOpts := NewLegacyOptions()

			// Set upstreams and related options to test their conversion
			flushInterval := Duration(5 * time.Second)
			timeout := Duration(5 * time.Second)
			legacyOpts.LegacyUpstreams.FlushInterval = time.Duration(flushInterval)
			legacyOpts.LegacyUpstreams.Timeout = time.Duration(timeout)
			legacyOpts.LegacyUpstreams.PassHostHeader = true
			legacyOpts.LegacyUpstreams.ProxyWebSockets = true
			legacyOpts.LegacyUpstreams.SSLUpstreamInsecureSkipVerify = true
			legacyOpts.LegacyUpstreams.Upstreams = []string{"http://foo.bar/baz", "file:///var/lib/website#/bar", "static://204"}
			legacyOpts.LegacyProvider.ClientID = "oauth-proxy"

			truth := true
			staticCode := 204
			opts.UpstreamServers = UpstreamConfig{
				Upstreams: []Upstream{
					{
						ID:                    "/baz",
						Path:                  "/baz",
						URI:                   "http://foo.bar/baz",
						FlushInterval:         &flushInterval,
						InsecureSkipTLSVerify: true,
						PassHostHeader:        &truth,
						ProxyWebSockets:       &truth,
						Timeout:               &timeout,
					},
					{
						ID:                    "/bar",
						Path:                  "/bar",
						URI:                   "file:///var/lib/website",
						FlushInterval:         &flushInterval,
						InsecureSkipTLSVerify: true,
						PassHostHeader:        &truth,
						ProxyWebSockets:       &truth,
						Timeout:               &timeout,
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
						Timeout:               nil,
					},
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

			opts.Server = Server{
				BindAddress: "127.0.0.1:4180",
			}

			opts.Providers[0].ClientID = "oauth-proxy"
			opts.Providers[0].ID = "google=oauth-proxy"
			opts.Providers[0].OIDCConfig.InsecureSkipNonce = true
			opts.Providers[0].OIDCConfig.AudienceClaims = []string{"aud"}
			opts.Providers[0].OIDCConfig.ExtraAudiences = []string{}
			opts.Providers[0].LoginURLParameters = []LoginURLParameter{
				{Name: "approval_prompt", Default: []string{"force"}},
			}

			converted, err := legacyOpts.ToOptions()
			Expect(err).ToNot(HaveOccurred())
			Expect(converted).To(Equal(opts))
		})
	})

	Context("Legacy Upstreams", func() {
		type convertUpstreamsTableInput struct {
			upstreamStrings   []string
			expectedUpstreams []Upstream
			errMsg            string
		}

		// Non defaults for these options
		skipVerify := true
		passHostHeader := false
		proxyWebSockets := true
		flushInterval := Duration(5 * time.Second)
		timeout := Duration(5 * time.Second)

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
			Timeout:               &timeout,
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
			Timeout:               &timeout,
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
			Timeout:               &timeout,
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
			Timeout:               nil,
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
			Timeout:               nil,
		}

		invalidHTTP := ":foo"
		invalidHTTPErrMsg := "could not parse upstream \":foo\": parse \":foo\": missing protocol scheme"

		DescribeTable("convertLegacyUpstreams",
			func(in *convertUpstreamsTableInput) {
				legacyUpstreams := LegacyUpstreams{
					Upstreams:                     in.upstreamStrings,
					SSLUpstreamInsecureSkipVerify: skipVerify,
					PassHostHeader:                passHostHeader,
					ProxyWebSockets:               proxyWebSockets,
					FlushInterval:                 time.Duration(flushInterval),
					Timeout:                       time.Duration(timeout),
				}

				upstreams, err := legacyUpstreams.convert()

				if in.errMsg != "" {
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(Equal(in.errMsg))
				} else {
					Expect(err).ToNot(HaveOccurred())
				}

				Expect(upstreams.Upstreams).To(ConsistOf(in.expectedUpstreams))
			},
			Entry("with no upstreams", &convertUpstreamsTableInput{
				upstreamStrings:   []string{},
				expectedUpstreams: []Upstream{},
				errMsg:            "",
			}),
			Entry("with a valid HTTP upstream", &convertUpstreamsTableInput{
				upstreamStrings:   []string{validHTTP},
				expectedUpstreams: []Upstream{validHTTPUpstream},
				errMsg:            "",
			}),
			Entry("with a HTTP upstream with an empty path", &convertUpstreamsTableInput{
				upstreamStrings:   []string{emptyPathHTTP},
				expectedUpstreams: []Upstream{emptyPathHTTPUpstream},
				errMsg:            "",
			}),
			Entry("with a valid File upstream with a fragment", &convertUpstreamsTableInput{
				upstreamStrings:   []string{validFileWithFragment},
				expectedUpstreams: []Upstream{validFileWithFragmentUpstream},
				errMsg:            "",
			}),
			Entry("with a valid static upstream", &convertUpstreamsTableInput{
				upstreamStrings:   []string{validStatic},
				expectedUpstreams: []Upstream{validStaticUpstream},
				errMsg:            "",
			}),
			Entry("with an invalid static upstream, code is 200", &convertUpstreamsTableInput{
				upstreamStrings:   []string{invalidStatic},
				expectedUpstreams: []Upstream{invalidStaticUpstream},
				errMsg:            "",
			}),
			Entry("with an invalid HTTP upstream", &convertUpstreamsTableInput{
				upstreamStrings:   []string{invalidHTTP},
				expectedUpstreams: []Upstream{},
				errMsg:            invalidHTTPErrMsg,
			}),
			Entry("with an invalid HTTP upstream and other upstreams", &convertUpstreamsTableInput{
				upstreamStrings:   []string{validHTTP, invalidHTTP},
				expectedUpstreams: []Upstream{},
				errMsg:            invalidHTTPErrMsg,
			}),
			Entry("with multiple valid upstreams", &convertUpstreamsTableInput{
				upstreamStrings:   []string{validHTTP, validFileWithFragment, validStatic},
				expectedUpstreams: []Upstream{validHTTPUpstream, validFileWithFragmentUpstream, validStaticUpstream},
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
						Claim:  "user",
						Prefix: "Basic ",
						BasicAuthPassword: &SecretSource{
							Value: []byte(basicAuthSecret),
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
						Claim:  "email",
						Prefix: "Basic ",
						BasicAuthPassword: &SecretSource{
							Value: []byte(basicAuthSecret),
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

	Context("Legacy Servers", func() {
		type legacyServersTableInput struct {
			legacyServer          LegacyServer
			expectedAppServer     Server
			expectedMetricsServer Server
		}

		const (
			insecureAddr        = "127.0.0.1:8080"
			insecureMetricsAddr = ":9090"
			secureAddr          = ":443"
			secureMetricsAddr   = ":9443"
			crtPath             = "tls.crt"
			keyPath             = "tls.key"
			minVersion          = "TLS1.3"
		)
		cipherSuites := []string{"TLS_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_AES_256_GCM_SHA384"}

		var tlsConfig = &TLS{
			Cert: &SecretSource{
				FromFile: crtPath,
			},
			Key: &SecretSource{
				FromFile: keyPath,
			},
		}

		var tlsConfigMinVersion = &TLS{
			Cert:       tlsConfig.Cert,
			Key:        tlsConfig.Key,
			MinVersion: minVersion,
		}

		var tlsConfigCipherSuites = &TLS{
			Cert: tlsConfig.Cert,
			Key:  tlsConfig.Key,
			CipherSuites: []string{
				"TLS_RSA_WITH_AES_128_GCM_SHA256",
				"TLS_RSA_WITH_AES_256_GCM_SHA384",
			},
		}

		DescribeTable("should convert to app and metrics servers",
			func(in legacyServersTableInput) {
				appServer, metricsServer := in.legacyServer.convert()
				Expect(appServer).To(Equal(in.expectedAppServer))
				Expect(metricsServer).To(Equal(in.expectedMetricsServer))
			},
			Entry("with default options only starts app HTTP server", legacyServersTableInput{
				legacyServer: LegacyServer{
					HTTPAddress:  insecureAddr,
					HTTPSAddress: secureAddr,
				},
				expectedAppServer: Server{
					BindAddress: insecureAddr,
				},
			}),
			Entry("with TLS options specified only starts app HTTPS server", legacyServersTableInput{
				legacyServer: LegacyServer{
					HTTPAddress:  insecureAddr,
					HTTPSAddress: secureAddr,
					TLSKeyFile:   keyPath,
					TLSCertFile:  crtPath,
				},
				expectedAppServer: Server{
					SecureBindAddress: secureAddr,
					TLS:               tlsConfig,
				},
			}),
			Entry("with TLS options specified with MinVersion", legacyServersTableInput{
				legacyServer: LegacyServer{
					HTTPAddress:   insecureAddr,
					HTTPSAddress:  secureAddr,
					TLSKeyFile:    keyPath,
					TLSCertFile:   crtPath,
					TLSMinVersion: minVersion,
				},
				expectedAppServer: Server{
					SecureBindAddress: secureAddr,
					TLS:               tlsConfigMinVersion,
				},
			}),
			Entry("with TLS options specified with CipherSuites", legacyServersTableInput{
				legacyServer: LegacyServer{
					HTTPAddress:     insecureAddr,
					HTTPSAddress:    secureAddr,
					TLSKeyFile:      keyPath,
					TLSCertFile:     crtPath,
					TLSCipherSuites: cipherSuites,
				},
				expectedAppServer: Server{
					SecureBindAddress: secureAddr,
					TLS:               tlsConfigCipherSuites,
				},
			}),
			Entry("with metrics HTTP and HTTPS addresses", legacyServersTableInput{
				legacyServer: LegacyServer{
					HTTPAddress:          insecureAddr,
					HTTPSAddress:         secureAddr,
					MetricsAddress:       insecureMetricsAddr,
					MetricsSecureAddress: secureMetricsAddr,
				},
				expectedAppServer: Server{
					BindAddress: insecureAddr,
				},
				expectedMetricsServer: Server{
					BindAddress:       insecureMetricsAddr,
					SecureBindAddress: secureMetricsAddr,
				},
			}),
			Entry("with metrics HTTPS and tls cert/key", legacyServersTableInput{
				legacyServer: LegacyServer{
					HTTPAddress:          insecureAddr,
					HTTPSAddress:         secureAddr,
					MetricsAddress:       insecureMetricsAddr,
					MetricsSecureAddress: secureMetricsAddr,
					MetricsTLSKeyFile:    keyPath,
					MetricsTLSCertFile:   crtPath,
				},
				expectedAppServer: Server{
					BindAddress: insecureAddr,
				},
				expectedMetricsServer: Server{
					BindAddress:       insecureMetricsAddr,
					SecureBindAddress: secureMetricsAddr,
					TLS:               tlsConfig,
				},
			}),
		)
	})

	Context("Legacy Providers", func() {
		type convertProvidersTableInput struct {
			legacyProvider    LegacyProvider
			expectedProviders Providers
			errMsg            string
		}

		// Non defaults for these options
		clientID := "abcd"

		defaultURLParams := []LoginURLParameter{
			{Name: "approval_prompt", Default: []string{"force"}},
		}

		defaultProvider := Provider{
			ID:                 "google=" + clientID,
			ClientID:           clientID,
			Type:               "google",
			LoginURLParameters: defaultURLParams,
		}
		defaultLegacyProvider := LegacyProvider{
			ClientID:     clientID,
			ProviderType: "google",
		}

		defaultProviderWithPrompt := Provider{
			ID:       "google=" + clientID,
			ClientID: clientID,
			Type:     "google",
			LoginURLParameters: []LoginURLParameter{
				{Name: "prompt", Default: []string{"switch_user"}},
			},
		}
		defaultLegacyProviderWithPrompt := LegacyProvider{
			ClientID:     clientID,
			ProviderType: "google",
			Prompt:       "switch_user",
		}

		displayNameProvider := Provider{
			ID:                 "displayName",
			Name:               "displayName",
			ClientID:           clientID,
			Type:               "google",
			LoginURLParameters: defaultURLParams,
		}

		displayNameLegacyProvider := LegacyProvider{
			ClientID:     clientID,
			ProviderName: "displayName",
			ProviderType: "google",
		}

		internalConfigProvider := Provider{
			ID:       "google=" + clientID,
			ClientID: clientID,
			Type:     "google",
			GoogleConfig: GoogleOptions{
				AdminEmail:         "email@email.com",
				ServiceAccountJSON: "test.json",
				Groups:             []string{"1", "2"},
			},
			LoginURLParameters: defaultURLParams,
		}

		internalConfigLegacyProvider := LegacyProvider{
			ClientID:                 clientID,
			ProviderType:             "google",
			GoogleAdminEmail:         "email@email.com",
			GoogleServiceAccountJSON: "test.json",
			GoogleGroups:             []string{"1", "2"},
		}

		legacyConfigLegacyProvider := LegacyProvider{
			ClientID:                 clientID,
			ProviderType:             "google",
			GoogleAdminEmail:         "email@email.com",
			GoogleServiceAccountJSON: "test.json",
			GoogleGroupsLegacy:       []string{"1", "2"},
		}
		DescribeTable("convertLegacyProviders",
			func(in *convertProvidersTableInput) {
				providers, err := in.legacyProvider.convert()

				if in.errMsg != "" {
					Expect(err).To(HaveOccurred())
					Expect(err.Error()).To(Equal(in.errMsg))
				} else {
					Expect(err).ToNot(HaveOccurred())
				}

				Expect(providers).To(ConsistOf(in.expectedProviders))
			},
			Entry("with default provider", &convertProvidersTableInput{
				legacyProvider:    defaultLegacyProvider,
				expectedProviders: Providers{defaultProvider},
				errMsg:            "",
			}),
			Entry("with prompt setting", &convertProvidersTableInput{
				legacyProvider:    defaultLegacyProviderWithPrompt,
				expectedProviders: Providers{defaultProviderWithPrompt},
				errMsg:            "",
			}),
			Entry("with provider display name", &convertProvidersTableInput{
				legacyProvider:    displayNameLegacyProvider,
				expectedProviders: Providers{displayNameProvider},
				errMsg:            "",
			}),
			Entry("with internal provider config", &convertProvidersTableInput{
				legacyProvider:    internalConfigLegacyProvider,
				expectedProviders: Providers{internalConfigProvider},
				errMsg:            "",
			}),
			Entry("with legacy provider config", &convertProvidersTableInput{
				legacyProvider:    legacyConfigLegacyProvider,
				expectedProviders: Providers{internalConfigProvider},
				errMsg:            "",
			}),
		)
	})
})
