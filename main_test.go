package main

import (
	"errors"
	"os"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	. "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options/testutil"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util/ptr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/format"
	"github.com/spf13/pflag"
)

var _ = Describe("Configuration Loading Suite", func() {
	// For comparing the full configuration differences of our structs we need to increase the gomega limits
	format.MaxLength = 50000
	format.MaxDepth = 10

	const testLegacyConfig = `
http_address="127.0.0.1:4180"
upstreams="http://httpbin"
set_basic_auth="true"
basic_auth_password="c3VwZXItc2VjcmV0LXBhc3N3b3Jk"
client_id="oauth2-proxy"
client_secret="b2F1dGgyLXByb3h5LWNsaWVudC1zZWNyZXQK"
google_admin_email="admin@example.com"
google_target_principal="principal"
`

	const testAlphaConfig = `
upstreamConfig:
  upstreams:
  - id: /
    path: /
    uri: http://httpbin
    flushInterval: 1s
    passHostHeader: true
    proxyWebSockets: true
    timeout: 30s
    insecureSkipTLSVerify: false
    disableKeepAlives: false
injectRequestHeaders:
- name: Authorization
  preserveRequestValue: false
  values:
  - claimSource:
      claim: user
      prefix: "Basic "
      basicAuthPassword:
        value: c3VwZXItc2VjcmV0LXBhc3N3b3Jk
- name: X-Forwarded-Groups
  preserveRequestValue: false
  values:
  - claimSource:
      claim: groups
- name: X-Forwarded-User
  preserveRequestValue: false
  values:
  - claimSource:
      claim: user
- name: X-Forwarded-Email
  preserveRequestValue: false
  values:
  - claimSource:
      claim: email
- name: X-Forwarded-Preferred-Username
  preserveRequestValue: false
  values:
  - claimSource:
      claim: preferred_username
injectResponseHeaders:
- name: Authorization
  values:
  - claimSource:
      claim: user
      prefix: "Basic "
      basicAuthPassword:
        value: c3VwZXItc2VjcmV0LXBhc3N3b3Jk
server:
  bindAddress: "127.0.0.1:4180"
providers:
- id: google=oauth2-proxy
  provider: google
  clientSecret: b2F1dGgyLXByb3h5LWNsaWVudC1zZWNyZXQK
  clientID: oauth2-proxy
  useSystemTrustStore: false
  skipClaimsFromProfileURL: false
  googleConfig:
    adminEmail: admin@example.com
    targetPrincipal: principal
    useApplicationDefaultCredentials: false
  oidcConfig:
    groupsClaim: groups
    emailClaim: email
    userIDClaim: email
    insecureSkipIssuerVerification: false
    insecureSkipNonce: true
    audienceClaims: [aud]
    extraAudiences: []
  loginURLParameters:
  - name: approval_prompt
    default:
    - force
`

	const testCoreConfig = `
cookie_secret="OQINaROshtE9TcZkNAm-5Zs2Pv3xaWytBmc5W7sPX7w="
email_domains="example.com"
cookie_secure="false"

redirect_url="http://localhost:4180/oauth2/callback"
`

	testExpectedOptions := func() *options.Options {
		opts, err := options.NewLegacyOptions().ToOptions()
		Expect(err).ToNot(HaveOccurred())

		opts.Cookie.Secret = "OQINaROshtE9TcZkNAm-5Zs2Pv3xaWytBmc5W7sPX7w="
		opts.EmailDomains = []string{"example.com"}
		opts.Cookie.Secure = false
		opts.RawRedirectURL = "http://localhost:4180/oauth2/callback"

		opts.UpstreamServers = options.UpstreamConfig{
			Upstreams: []options.Upstream{
				{
					ID:                    "/",
					Path:                  "/",
					URI:                   "http://httpbin",
					FlushInterval:         ptr.Ptr(options.DefaultUpstreamFlushInterval),
					PassHostHeader:        ptr.Ptr(true),
					ProxyWebSockets:       ptr.Ptr(true),
					Timeout:               ptr.Ptr(options.DefaultUpstreamTimeout),
					InsecureSkipTLSVerify: ptr.Ptr(false),
					DisableKeepAlives:     ptr.Ptr(false),
				},
			},
		}

		authHeader := options.Header{
			Name: "Authorization",
			Values: []options.HeaderValue{
				{
					ClaimSource: &options.ClaimSource{
						Claim:  "user",
						Prefix: "Basic ",
						BasicAuthPassword: &options.SecretSource{
							Value: []byte("c3VwZXItc2VjcmV0LXBhc3N3b3Jk"),
						},
					},
				},
			},
		}

		authHeader.PreserveRequestValue = ptr.Ptr(false)
		opts.InjectRequestHeaders = append([]options.Header{authHeader}, opts.InjectRequestHeaders...)

		authHeader.PreserveRequestValue = nil
		opts.InjectResponseHeaders = append(opts.InjectResponseHeaders, authHeader)

		opts.Providers = options.Providers{
			options.Provider{
				ID:                       "google=oauth2-proxy",
				Type:                     "google",
				ClientSecret:             "b2F1dGgyLXByb3h5LWNsaWVudC1zZWNyZXQK",
				ClientID:                 "oauth2-proxy",
				UseSystemTrustStore:      ptr.Ptr(false),
				SkipClaimsFromProfileURL: ptr.Ptr(false),
				GoogleConfig: options.GoogleOptions{
					AdminEmail:                       "admin@example.com",
					UseApplicationDefaultCredentials: ptr.Ptr(false),
					TargetPrincipal:                  "principal",
				},
				AzureConfig: options.AzureOptions{
					Tenant: "common",
				},
				OIDCConfig: options.OIDCOptions{
					GroupsClaim:                    "groups",
					EmailClaim:                     "email",
					UserIDClaim:                    "email",
					AudienceClaims:                 []string{"aud"},
					ExtraAudiences:                 []string{},
					InsecureSkipNonce:              ptr.Ptr(true),
					InsecureAllowUnverifiedEmail:   ptr.Ptr(false),
					InsecureSkipIssuerVerification: ptr.Ptr(false),
					SkipDiscovery:                  ptr.Ptr(false),
				},
				LoginURLParameters: []options.LoginURLParameter{
					{Name: "approval_prompt", Default: []string{"force"}},
				},
			},
		}
		return opts
	}

	type loadConfigurationTableInput struct {
		configContent      string
		alphaConfigContent string
		args               []string
		extraFlags         func() *pflag.FlagSet
		expectedOptions    func() *options.Options
		expectedErr        error
	}

	DescribeTable("LoadConfiguration",
		func(in loadConfigurationTableInput) {
			var configFileName, alphaConfigFileName string

			defer func() {
				if configFileName != "" {
					Expect(os.Remove(configFileName)).To(Succeed())
				}
				if alphaConfigFileName != "" {
					Expect(os.Remove(alphaConfigFileName)).To(Succeed())
				}
			}()

			if in.configContent != "" {
				By("Writing the config to a temporary file", func() {
					file, err := os.CreateTemp("", "oauth2-proxy-test-config-XXXX.cfg")
					Expect(err).ToNot(HaveOccurred())
					defer file.Close()

					configFileName = file.Name()

					_, err = file.WriteString(in.configContent)
					Expect(err).ToNot(HaveOccurred())
				})
			}

			if in.alphaConfigContent != "" {
				By("Writing the config to a temporary file", func() {
					file, err := os.CreateTemp("", "oauth2-proxy-test-alpha-config-XXXX.yaml")
					Expect(err).ToNot(HaveOccurred())
					defer file.Close()

					alphaConfigFileName = file.Name()

					_, err = file.WriteString(in.alphaConfigContent)
					Expect(err).ToNot(HaveOccurred())
				})
			}

			extraFlags := pflag.NewFlagSet("test-flagset", pflag.ExitOnError)
			if in.extraFlags != nil {
				extraFlags = in.extraFlags()
			}

			opts, err := loadConfiguration(configFileName, alphaConfigFileName, extraFlags, in.args)
			if in.expectedErr != nil {
				Expect(err).To(MatchError(ContainSubstring(in.expectedErr.Error())))
			} else {
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(in.expectedOptions).ToNot(BeNil())
			Expect(opts).To(EqualOpts(in.expectedOptions()))
		},
		Entry("with legacy configuration", loadConfigurationTableInput{
			configContent:   testCoreConfig + testLegacyConfig,
			expectedOptions: testExpectedOptions,
		}),
		Entry("with alpha configuration", loadConfigurationTableInput{
			configContent:      testCoreConfig,
			alphaConfigContent: testAlphaConfig,
			expectedOptions:    testExpectedOptions,
		}),
		Entry("with bad legacy configuration", loadConfigurationTableInput{
			configContent:   testCoreConfig + "unknown_field=\"something\"",
			expectedOptions: func() *options.Options { return nil },
			expectedErr:     errors.New("failed to load legacy options: failed to load config: error unmarshalling config: decoding failed due to the following error(s):\n\n'' has invalid keys: unknown_field"),
		}),
		Entry("with bad alpha configuration", loadConfigurationTableInput{
			configContent:      testCoreConfig,
			alphaConfigContent: testAlphaConfig + ":",
			expectedOptions:    func() *options.Options { return nil },
			expectedErr:        errors.New("failed to load alpha options: error unmarshalling config: yaml: line 1: did not find expected key"),
		}),
		Entry("with alpha configuration and bad core configuration", loadConfigurationTableInput{
			configContent:      testCoreConfig + "unknown_field=\"something\"",
			alphaConfigContent: testAlphaConfig,
			expectedOptions:    func() *options.Options { return nil },
			expectedErr:        errors.New("failed to load legacy options: failed to load config: error unmarshalling config: decoding failed due to the following error(s):\n\n'' has invalid keys: unknown_field"),
		}),
	)
})
