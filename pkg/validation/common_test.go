package validation

import (
	"os"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Common", func() {
	var validSecretSourceValue []byte
	const validSecretSourceEnv = "OAUTH2_PROXY_TEST_SECRET_SOURCE_ENV"
	var validSecretSourceFile string

	BeforeEach(func() {
		validSecretSourceValue = []byte("This is a secret source value")
		Expect(os.Setenv(validSecretSourceEnv, "This is a secret source env")).To(Succeed())
		tmp, err := os.CreateTemp("", "oauth2-proxy-secret-source-test")
		Expect(err).ToNot(HaveOccurred())
		defer tmp.Close()

		_, err = tmp.Write([]byte("This is a secret source file"))
		Expect(err).ToNot(HaveOccurred())

		validSecretSourceFile = tmp.Name()
	})

	AfterEach(func() {
		Expect(os.Unsetenv(validSecretSourceEnv)).To(Succeed())
		Expect(os.Remove(validSecretSourceFile)).To(Succeed())
	})

	type validateSecretSourceTableInput struct {
		source      func() options.SecretSource
		expectedMsg string
	}

	DescribeTable("validateSecretSource should",
		func(in validateSecretSourceTableInput) {
			Expect(validateSecretSource(in.source())).To(Equal(in.expectedMsg))
		},
		Entry("with no entries", validateSecretSourceTableInput{
			source: func() options.SecretSource {
				return options.SecretSource{}
			},
			expectedMsg: multipleValuesForSecretSource,
		}),
		Entry("with a Value and FromEnv", validateSecretSourceTableInput{
			source: func() options.SecretSource {
				return options.SecretSource{
					Value:   validSecretSourceValue,
					FromEnv: validSecretSourceEnv,
				}
			},
			expectedMsg: multipleValuesForSecretSource,
		}),
		Entry("with a Value and FromFile", validateSecretSourceTableInput{
			source: func() options.SecretSource {
				return options.SecretSource{
					Value:    validSecretSourceValue,
					FromFile: validSecretSourceFile,
				}
			},
			expectedMsg: multipleValuesForSecretSource,
		}),
		Entry("with FromEnv and FromFile", validateSecretSourceTableInput{
			source: func() options.SecretSource {
				return options.SecretSource{
					FromEnv:  validSecretSourceEnv,
					FromFile: validSecretSourceFile,
				}
			},
			expectedMsg: multipleValuesForSecretSource,
		}),
		Entry("with a Value, FromEnv and FromFile", validateSecretSourceTableInput{
			source: func() options.SecretSource {
				return options.SecretSource{
					Value:    validSecretSourceValue,
					FromEnv:  validSecretSourceEnv,
					FromFile: validSecretSourceFile,
				}
			},
			expectedMsg: multipleValuesForSecretSource,
		}),
		Entry("with a valid Value", validateSecretSourceTableInput{
			source: func() options.SecretSource {
				return options.SecretSource{
					Value: validSecretSourceValue,
				}
			},
			expectedMsg: "",
		}),
		Entry("with a valid FromEnv", validateSecretSourceTableInput{
			source: func() options.SecretSource {
				return options.SecretSource{
					FromEnv: validSecretSourceEnv,
				}
			},
			expectedMsg: "",
		}),
		Entry("with a valid FromFile", validateSecretSourceTableInput{
			source: func() options.SecretSource {
				return options.SecretSource{
					FromFile: validSecretSourceFile,
				}
			},
			expectedMsg: "",
		}),
		Entry("with an invalid FromEnv", validateSecretSourceTableInput{
			source: func() options.SecretSource {
				return options.SecretSource{
					FromEnv: "INVALID_ENV",
				}
			},
			expectedMsg: "error loading secret from environent: no value for for key \"INVALID_ENV\"",
		}),
		Entry("with an invalid FromFile", validateSecretSourceTableInput{
			source: func() options.SecretSource {
				return options.SecretSource{
					FromFile: "invalidFile",
				}
			},
			expectedMsg: "error loadig secret from file: stat invalidFile: no such file or directory",
		}),
	)
})
