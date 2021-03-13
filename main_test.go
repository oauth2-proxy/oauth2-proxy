package main

import (
	"errors"
	"io/ioutil"
	"os"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/spf13/pflag"
)

var _ = Describe("Configuration Loading Suite", func() {
	const testLegacyConfig = `
http_address="127.0.0.1:4180"
upstreams="http://httpbin"
set_basic_auth="true"
basic_auth_password="super-secret-password"
`

	const testAlphaConfig = `
upstreams:
  - id: /
    path: /
    uri: http://httpbin
    flushInterval: 1s
    passHostHeader: true
    proxyWebSockets: true
injectRequestHeaders:
- name: Authorization
  values:
  - claim: user
    prefix: "Basic "
    basicAuthPassword:
      value: c3VwZXItc2VjcmV0LXBhc3N3b3Jk
- name: X-Forwarded-Groups
  values:
  - claim: groups
- name: X-Forwarded-User
  values:
  - claim: user
- name: X-Forwarded-Email
  values:
  - claim: email
- name: X-Forwarded-Preferred-Username
  values:
  - claim: preferred_username
injectResponseHeaders:
- name: Authorization
  values:
  - claim: user
    prefix: "Basic "
    basicAuthPassword:
      value: c3VwZXItc2VjcmV0LXBhc3N3b3Jk
server:
  bindAddress: "127.0.0.1:4180"
`

	const testCoreConfig = `
cookie_secret="OQINaROshtE9TcZkNAm-5Zs2Pv3xaWytBmc5W7sPX7w="
provider="oidc"
email_domains="example.com"
oidc_issuer_url="http://dex.localhost:4190/dex"
client_secret="b2F1dGgyLXByb3h5LWNsaWVudC1zZWNyZXQK"
client_id="oauth2-proxy"
cookie_secure="false"

redirect_url="http://localhost:4180/oauth2/callback"
`

	boolPtr := func(b bool) *bool {
		return &b
	}

	durationPtr := func(d time.Duration) *options.Duration {
		du := options.Duration(d)
		return &du
	}

	testExpectedOptions := func() *options.Options {
		opts, err := options.NewLegacyOptions().ToOptions()
		Expect(err).ToNot(HaveOccurred())

		opts.Cookie.Secret = "OQINaROshtE9TcZkNAm-5Zs2Pv3xaWytBmc5W7sPX7w="
		opts.ProviderType = "oidc"
		opts.EmailDomains = []string{"example.com"}
		opts.OIDCIssuerURL = "http://dex.localhost:4190/dex"
		opts.ClientSecret = "b2F1dGgyLXByb3h5LWNsaWVudC1zZWNyZXQK"
		opts.ClientID = "oauth2-proxy"
		opts.Cookie.Secure = false
		opts.RawRedirectURL = "http://localhost:4180/oauth2/callback"

		opts.UpstreamServers = options.Upstreams{
			{
				ID:              "/",
				Path:            "/",
				URI:             "http://httpbin",
				FlushInterval:   durationPtr(options.DefaultUpstreamFlushInterval),
				PassHostHeader:  boolPtr(true),
				ProxyWebSockets: boolPtr(true),
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
							Value: []byte("super-secret-password"),
						},
					},
				},
			},
		}

		opts.InjectRequestHeaders = append([]options.Header{authHeader}, opts.InjectRequestHeaders...)
		opts.InjectResponseHeaders = append(opts.InjectResponseHeaders, authHeader)
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
					file, err := ioutil.TempFile("", "oauth2-proxy-test-config-XXXX.cfg")
					Expect(err).ToNot(HaveOccurred())
					defer file.Close()

					configFileName = file.Name()

					_, err = file.WriteString(in.configContent)
					Expect(err).ToNot(HaveOccurred())
				})
			}

			if in.alphaConfigContent != "" {
				By("Writing the config to a temporary file", func() {
					file, err := ioutil.TempFile("", "oauth2-proxy-test-alpha-config-XXXX.yaml")
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
				Expect(err).To(MatchError(in.expectedErr.Error()))
			} else {
				Expect(err).ToNot(HaveOccurred())
			}
			Expect(in.expectedOptions).ToNot(BeNil())
			Expect(opts).To(Equal(in.expectedOptions()))
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
			expectedErr:     errors.New("failed to load config: error unmarshalling config: 1 error(s) decoding:\n\n* '' has invalid keys: unknown_field"),
		}),
		Entry("with bad alpha configuration", loadConfigurationTableInput{
			configContent:      testCoreConfig,
			alphaConfigContent: testAlphaConfig + ":",
			expectedOptions:    func() *options.Options { return nil },
			expectedErr:        errors.New("failed to load alpha options: error unmarshalling config: error converting YAML to JSON: yaml: line 36: did not find expected key"),
		}),
		Entry("with alpha configuration and bad core configuration", loadConfigurationTableInput{
			configContent:      testCoreConfig + "unknown_field=\"something\"",
			alphaConfigContent: testAlphaConfig,
			expectedOptions:    func() *options.Options { return nil },
			expectedErr:        errors.New("failed to load core options: failed to load config: error unmarshalling config: 1 error(s) decoding:\n\n* '' has invalid keys: unknown_field"),
		}),
	)
})
