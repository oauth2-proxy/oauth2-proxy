package options

import (
	"fmt"
	"io/ioutil"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
	"github.com/spf13/pflag"
)

var _ = Describe("Load", func() {
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
					configFile, err := ioutil.TempFile("", "oauth2-proxy-test-legacy-config-file")
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
				Expect(input).To(Equal(o.expectedOutput))
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
				expectedErr:    fmt.Errorf("unable to load config file: While parsing config: (1, 16): never reached"),
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
				expectedOutput: NewOptions(),
			}),
			Entry("with an empty LegacyOptions struct, should return default values", &testOptionsTableInput{
				flagSet:        NewFlagSet,
				input:          &LegacyOptions{},
				expectedOutput: NewLegacyOptions(),
			}),
		)
	})
})
