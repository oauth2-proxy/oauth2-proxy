package options

import (
	"errors"
	"fmt"
	"os"
	"time"

	. "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options/testutil"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spf13/pflag"
)

var _ = Describe("Load", func() {
	optionsWithNilProvider := NewOptions()
	optionsWithNilProvider.Providers = nil

	legacyOptionsWithNilProvider := &LegacyOptions{
		LegacyUpstreams: LegacyUpstreams{
			PassHostHeader:  true,
			ProxyWebSockets: true,
			FlushInterval:   DefaultUpstreamFlushInterval,
			Timeout:         DefaultUpstreamTimeout,
		},

		LegacyHeaders: LegacyHeaders{
			PassBasicAuth:        true,
			PassUserHeaders:      true,
			SkipAuthStripHeaders: true,
		},

		LegacyServer: LegacyServer{
			HTTPAddress:  "127.0.0.1:4180",
			HTTPSAddress: ":443",
		},

		LegacyProvider: LegacyProvider{
			ProviderType:          "google",
			AzureTenant:           "common",
			ApprovalPrompt:        "force",
			UserIDClaim:           "email",
			OIDCEmailClaim:        "email",
			OIDCGroupsClaim:       "groups",
			OIDCAudienceClaims:    []string{"aud"},
			InsecureOIDCSkipNonce: true,
		},

		Options: Options{
			ProxyPrefix:        "/oauth2",
			PingPath:           "/ping",
			ReadyPath:          "/ready",
			RealClientIPHeader: "X-Real-IP",
			ForceHTTPS:         false,
			Cookie:             cookieDefaults(),
			Session:            sessionOptionsDefaults(),
			Templates:          templatesDefaults(),
			SkipAuthPreflight:  false,
			Logging:            loggingDefaults(),
		},
	}

	Context("with a testOptions structure", func() {
		type TestOptionSubStruct struct {
			StringSliceOption []string `flag:"string-slice-option" cfg:"string_slice_option"`
		}

		type TestOptions struct {
			StringOption string              `flag:"string-option" cfg:"string_option"`
			Sub          TestOptionSubStruct `cfg:",squash"`
			// Check exported but internal fields do not break loading
			Internal *string `cfg:",internal"`
			// Check unexported fields do not break loading
			unexported string
		}

		type MissingSquashTestOptions struct {
			StringOption string `flag:"string-option" cfg:"string_option"`
			Sub          TestOptionSubStruct
		}

		type MissingCfgTestOptions struct {
			StringOption string              `flag:"string-option"`
			Sub          TestOptionSubStruct `cfg:",squash"`
		}

		type MissingFlagTestOptions struct {
			StringOption string              `cfg:"string_option"`
			Sub          TestOptionSubStruct `cfg:",squash"`
		}

		var testOptionsConfigBytes = []byte(`
			string_option="foo"
			string_slice_option="a,b,c,d"
		`)

		var testOptionsFlagSet *pflag.FlagSet

		type testOptionsTableInput struct {
			env            map[string]string
			args           []string
			configFile     []byte
			flagSet        func() *pflag.FlagSet
			expectedErr    error
			input          interface{}
			expectedOutput interface{}
		}

		BeforeEach(func() {
			testOptionsFlagSet = pflag.NewFlagSet("testFlagSet", pflag.ExitOnError)
			testOptionsFlagSet.String("string-option", "default", "")
			testOptionsFlagSet.StringSlice("string-slice-option", []string{"a", "b"}, "")
		})

		DescribeTable("Load",
			func(o *testOptionsTableInput) {
				var configFileName string

				if o.configFile != nil {
					By("Creating a config file")
					configFile, err := os.CreateTemp("", "oauth2-proxy-test-legacy-config-file")
					Expect(err).ToNot(HaveOccurred())
					defer configFile.Close()

					_, err = configFile.Write(o.configFile)
					Expect(err).ToNot(HaveOccurred())
					defer os.Remove(configFile.Name())

					configFileName = configFile.Name()
				}

				if len(o.env) > 0 {
					By("Setting environment variables")
					for k, v := range o.env {
						os.Setenv(k, v)
						defer os.Unsetenv(k)
					}
				}

				Expect(o.flagSet).ToNot(BeNil())
				flagSet := o.flagSet()
				Expect(flagSet).ToNot(BeNil())

				if len(o.args) > 0 {
					By("Parsing flag arguments")
					Expect(flagSet.Parse(o.args)).To(Succeed())
				}

				var input interface{}
				if o.input != nil {
					input = o.input
				} else {
					input = &TestOptions{}
				}
				err := Load(configFileName, flagSet, input)
				if o.expectedErr != nil {
					Expect(err).To(MatchError(o.expectedErr.Error()))
				} else {
					Expect(err).ToNot(HaveOccurred())
				}
				Expect(input).To(EqualOpts(o.expectedOutput))
			},
			Entry("with just a config file", &testOptionsTableInput{
				configFile: testOptionsConfigBytes,
				flagSet:    func() *pflag.FlagSet { return testOptionsFlagSet },
				expectedOutput: &TestOptions{
					StringOption: "foo",
					Sub: TestOptionSubStruct{
						StringSliceOption: []string{"a", "b", "c", "d"},
					},
				},
			}),
			Entry("when setting env variables", &testOptionsTableInput{
				configFile: testOptionsConfigBytes,
				env: map[string]string{
					"OAUTH2_PROXY_STRING_OPTION":       "bar",
					"OAUTH2_PROXY_STRING_SLICE_OPTION": "a,b,c",
				},
				flagSet: func() *pflag.FlagSet { return testOptionsFlagSet },
				expectedOutput: &TestOptions{
					StringOption: "bar",
					Sub: TestOptionSubStruct{
						StringSliceOption: []string{"a", "b", "c"},
					},
				},
			}),
			Entry("when setting flags", &testOptionsTableInput{
				configFile: testOptionsConfigBytes,
				env: map[string]string{
					"OAUTH2_PROXY_STRING_OPTION":       "bar",
					"OAUTH2_PROXY_STRING_SLICE_OPTION": "a,b,c",
				},
				args: []string{
					"--string-option", "baz",
					"--string-slice-option", "a,b,c,d,e",
				},
				flagSet: func() *pflag.FlagSet { return testOptionsFlagSet },
				expectedOutput: &TestOptions{
					StringOption: "baz",
					Sub: TestOptionSubStruct{
						StringSliceOption: []string{"a", "b", "c", "d", "e"},
					},
				},
			}),
			Entry("when setting flags multiple times", &testOptionsTableInput{
				configFile: testOptionsConfigBytes,
				env: map[string]string{
					"OAUTH2_PROXY_STRING_OPTION":       "bar",
					"OAUTH2_PROXY_STRING_SLICE_OPTION": "a,b,c",
				},
				args: []string{
					"--string-option", "baz",
					"--string-slice-option", "x",
					"--string-slice-option", "y",
					"--string-slice-option", "z",
				},
				flagSet: func() *pflag.FlagSet { return testOptionsFlagSet },
				expectedOutput: &TestOptions{
					StringOption: "baz",
					Sub: TestOptionSubStruct{
						StringSliceOption: []string{"x", "y", "z"},
					},
				},
			}),
			Entry("when setting env variables without a config file", &testOptionsTableInput{
				env: map[string]string{
					"OAUTH2_PROXY_STRING_OPTION":       "bar",
					"OAUTH2_PROXY_STRING_SLICE_OPTION": "a,b,c",
				},
				flagSet: func() *pflag.FlagSet { return testOptionsFlagSet },
				expectedOutput: &TestOptions{
					StringOption: "bar",
					Sub: TestOptionSubStruct{
						StringSliceOption: []string{"a", "b", "c"},
					},
				},
			}),
			Entry("when setting flags without a config file", &testOptionsTableInput{
				env: map[string]string{
					"OAUTH2_PROXY_STRING_OPTION":       "bar",
					"OAUTH2_PROXY_STRING_SLICE_OPTION": "a,b,c",
				},
				args: []string{
					"--string-option", "baz",
					"--string-slice-option", "a,b,c,d,e",
				},
				flagSet: func() *pflag.FlagSet { return testOptionsFlagSet },
				expectedOutput: &TestOptions{
					StringOption: "baz",
					Sub: TestOptionSubStruct{
						StringSliceOption: []string{"a", "b", "c", "d", "e"},
					},
				},
			}),
			Entry("when setting flags without a config file", &testOptionsTableInput{
				env: map[string]string{
					"OAUTH2_PROXY_STRING_OPTION":       "bar",
					"OAUTH2_PROXY_STRING_SLICE_OPTION": "a,b,c",
				},
				args: []string{
					"--string-option", "baz",
					"--string-slice-option", "a,b,c,d,e",
				},
				flagSet: func() *pflag.FlagSet { return testOptionsFlagSet },
				expectedOutput: &TestOptions{
					StringOption: "baz",
					Sub: TestOptionSubStruct{
						StringSliceOption: []string{"a", "b", "c", "d", "e"},
					},
				},
			}),
			Entry("when nothing is set it should use flag defaults", &testOptionsTableInput{
				flagSet: func() *pflag.FlagSet { return testOptionsFlagSet },
				expectedOutput: &TestOptions{
					StringOption: "default",
					Sub: TestOptionSubStruct{
						StringSliceOption: []string{"a", "b"},
					},
				},
			}),
			Entry("with an invalid config file", &testOptionsTableInput{
				configFile:     []byte(`slice_option = foo`),
				flagSet:        func() *pflag.FlagSet { return testOptionsFlagSet },
				expectedErr:    fmt.Errorf("unable to load config file: While parsing config: toml: expected 'false'"),
				expectedOutput: &TestOptions{},
			}),
			Entry("with an invalid flagset", &testOptionsTableInput{
				flagSet: func() *pflag.FlagSet {
					// Missing a flag
					f := pflag.NewFlagSet("testFlagSet", pflag.ExitOnError)
					f.String("string-option", "default", "")
					return f
				},
				expectedErr:    fmt.Errorf("unable to register flags: field \"string-slice-option\" does not have a registered flag"),
				expectedOutput: &TestOptions{},
			}),
			Entry("with an struct is missing the squash tag", &testOptionsTableInput{
				flagSet:        func() *pflag.FlagSet { return testOptionsFlagSet },
				expectedErr:    fmt.Errorf("unable to register flags: field \".Sub\" does not have required cfg tag: `,squash`"),
				input:          &MissingSquashTestOptions{},
				expectedOutput: &MissingSquashTestOptions{},
			}),
			Entry("with a field is missing the cfg tag", &testOptionsTableInput{
				flagSet:        func() *pflag.FlagSet { return testOptionsFlagSet },
				expectedErr:    fmt.Errorf("unable to register flags: field \".StringOption\" does not have required tags (cfg, flag)"),
				input:          &MissingCfgTestOptions{},
				expectedOutput: &MissingCfgTestOptions{},
			}),
			Entry("with a field is missing the flag tag", &testOptionsTableInput{
				flagSet:        func() *pflag.FlagSet { return testOptionsFlagSet },
				expectedErr:    fmt.Errorf("unable to register flags: field \".StringOption\" does not have required tags (cfg, flag)"),
				input:          &MissingFlagTestOptions{},
				expectedOutput: &MissingFlagTestOptions{},
			}),
			Entry("with existing unexported fields", &testOptionsTableInput{
				flagSet: func() *pflag.FlagSet { return testOptionsFlagSet },
				input: &TestOptions{
					unexported: "unexported",
				},
				expectedOutput: &TestOptions{
					StringOption: "default",
					Sub: TestOptionSubStruct{
						StringSliceOption: []string{"a", "b"},
					},
					unexported: "unexported",
				},
			}),
			Entry("with an unknown option in the config file", &testOptionsTableInput{
				configFile:  []byte(`unknown_option="foo"`),
				flagSet:     func() *pflag.FlagSet { return testOptionsFlagSet },
				expectedErr: fmt.Errorf("error unmarshalling config: 1 error(s) decoding:\n\n* '' has invalid keys: unknown_option"),
				// Viper will unmarshal before returning the error, so this is the default output
				expectedOutput: &TestOptions{
					StringOption: "default",
					Sub: TestOptionSubStruct{
						StringSliceOption: []string{"a", "b"},
					},
				},
			}),
			Entry("with an empty Options struct, should return default values", &testOptionsTableInput{
				flagSet:        NewFlagSet,
				input:          &Options{},
				expectedOutput: optionsWithNilProvider,
			}),
			Entry("with an empty LegacyOptions struct, should return default values", &testOptionsTableInput{
				flagSet:        NewLegacyFlagSet,
				input:          &LegacyOptions{},
				expectedOutput: legacyOptionsWithNilProvider,
			}),
		)
	})
})

var _ = Describe("LoadYAML", func() {
	Context("with a testOptions structure", func() {
		type TestOptionSubStruct struct {
			StringSliceOption []string `yaml:"stringSliceOption,omitempty"`
		}

		type TestOptions struct {
			StringOption string              `yaml:"stringOption,omitempty"`
			Sub          TestOptionSubStruct `yaml:"sub,omitempty"`

			// Check that embedded fields can be unmarshalled
			TestOptionSubStruct `yaml:",inline,squash"`
		}

		var testOptionsConfigBytesFull = []byte(`
stringOption: foo
stringSliceOption:
- a
- b
- c
sub:
  stringSliceOption:
  - d
  - e
`)

		type loadYAMLTableInput struct {
			configFile     []byte
			input          interface{}
			expectedErr    error
			expectedOutput interface{}
		}

		DescribeTable("LoadYAML",
			func(in loadYAMLTableInput) {
				// Set the required environment variables before running the test
				os.Setenv("TESTUSER", "Alice")

				// Unset the environment variables after running the test
				defer os.Unsetenv("TESTUSER")

				var configFileName string
				if in.configFile != nil {
					By("Creating a config file")
					configFile, err := os.CreateTemp("", "oauth2-proxy-test-config-file")
					Expect(err).ToNot(HaveOccurred())
					defer configFile.Close()

					_, err = configFile.Write(in.configFile)
					Expect(err).ToNot(HaveOccurred())
					defer os.Remove(configFile.Name())

					configFileName = configFile.Name()
				}

				var input interface{}
				if in.input != nil {
					input = in.input
				} else {
					input = &TestOptions{}
				}

				err := LoadYAML(configFileName, input)
				if in.expectedErr != nil {
					Expect(err).To(MatchError(in.expectedErr.Error()))
				} else {
					Expect(err).ToNot(HaveOccurred())
				}
				Expect(input).To(EqualOpts(in.expectedOutput))
			},
			Entry("with a valid input", loadYAMLTableInput{
				configFile: testOptionsConfigBytesFull,
				input:      &TestOptions{},
				expectedOutput: &TestOptions{
					StringOption: "foo",
					Sub: TestOptionSubStruct{
						StringSliceOption: []string{"d", "e"},
					},
					TestOptionSubStruct: TestOptionSubStruct{
						StringSliceOption: []string{"a", "b", "c"},
					},
				},
			}),
			Entry("with no config file", loadYAMLTableInput{
				configFile:     nil,
				input:          &TestOptions{},
				expectedOutput: &TestOptions{},
				expectedErr:    errors.New("no configuration file provided"),
			}),
			Entry("with invalid YAML", loadYAMLTableInput{
				configFile:     []byte("\tfoo: bar"),
				input:          &TestOptions{},
				expectedOutput: &TestOptions{},
				expectedErr:    errors.New("error unmarshalling config: error converting YAML to JSON: yaml: found character that cannot start any token"),
			}),
			Entry("with extra fields in the YAML", loadYAMLTableInput{
				configFile: append(testOptionsConfigBytesFull, []byte("foo: bar\n")...),
				input:      &TestOptions{},
				expectedOutput: &TestOptions{
					StringOption: "foo",
					Sub: TestOptionSubStruct{
						StringSliceOption: []string{"d", "e"},
					},
					TestOptionSubStruct: TestOptionSubStruct{
						StringSliceOption: []string{"a", "b", "c"},
					},
				},
				expectedErr: errors.New("error unmarshalling config: error unmarshaling JSON: while decoding JSON: json: unknown field \"foo\""),
			}),
			Entry("with an incorrect type for a string field", loadYAMLTableInput{
				configFile:     []byte(`stringOption: ["a", "b"]`),
				input:          &TestOptions{},
				expectedOutput: &TestOptions{},
				expectedErr:    errors.New("error unmarshalling config: error unmarshaling JSON: while decoding JSON: json: cannot unmarshal array into Go struct field TestOptions.StringOption of type string"),
			}),
			Entry("with an incorrect type for an array field", loadYAMLTableInput{
				configFile:     []byte(`stringSliceOption: "a"`),
				input:          &TestOptions{},
				expectedOutput: &TestOptions{},
				expectedErr:    errors.New("error unmarshalling config: error unmarshaling JSON: while decoding JSON: json: cannot unmarshal string into Go struct field TestOptions.StringSliceOption of type []string"),
			}),
			Entry("with a config file containing environment variable references", loadYAMLTableInput{
				configFile: []byte("stringOption: ${TESTUSER}"),
				input:      &TestOptions{},
				expectedOutput: &TestOptions{
					StringOption: "Alice",
				},
			}),
			Entry("with a config file containing env variable references, with a fallback value", loadYAMLTableInput{
				configFile: []byte("stringOption: ${TESTUSER2=Bob}"),
				input:      &TestOptions{},
				expectedOutput: &TestOptions{
					StringOption: "Bob",
				},
			}),
		)
	})

	It("should load a full example AlphaOptions", func() {
		config := []byte(`
upstreamConfig:
  upstreams:
  - id: httpbin
    path: /
    uri: http://httpbin
    flushInterval: 500ms
injectRequestHeaders:
- name: X-Forwarded-User
  values:
  - claim: user
injectResponseHeaders:
- name: X-Secret
  values:
  - value: c2VjcmV0
`)

		By("Creating a config file")
		configFile, err := os.CreateTemp("", "oauth2-proxy-test-alpha-config-file")
		Expect(err).ToNot(HaveOccurred())
		defer configFile.Close()

		_, err = configFile.Write(config)
		Expect(err).ToNot(HaveOccurred())
		defer os.Remove(configFile.Name())

		configFileName := configFile.Name()

		By("Loading the example config")
		into := &AlphaOptions{}
		Expect(LoadYAML(configFileName, into)).To(Succeed())

		flushInterval := Duration(500 * time.Millisecond)

		Expect(into).To(Equal(&AlphaOptions{
			UpstreamConfig: UpstreamConfig{
				Upstreams: []Upstream{
					{
						ID:            "httpbin",
						Path:          "/",
						URI:           "http://httpbin",
						FlushInterval: &flushInterval,
					},
				},
			},
			InjectRequestHeaders: []Header{
				{
					Name: "X-Forwarded-User",
					Values: []HeaderValue{
						{
							ClaimSource: &ClaimSource{
								Claim: "user",
							},
						},
					},
				},
			},
			InjectResponseHeaders: []Header{
				{
					Name: "X-Secret",
					Values: []HeaderValue{
						{
							SecretSource: &SecretSource{
								Value: []byte("secret"),
							},
						},
					},
				},
			},
		}))
	})
})
