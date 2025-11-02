package util

import (
	"os"
	"path"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("GetSecretValue", func() {
	var fileDir string
	const secretEnvKey = "SECRET_ENV_KEY"
	const secretEnvValue = "secret-env-value"
	var secretFileValue = []byte("secret-file-value")

	BeforeEach(func() {
		os.Setenv(secretEnvKey, secretEnvValue)

		var err error
		fileDir, err = os.MkdirTemp("", "oauth2-proxy-util-get-secret-value")
		Expect(err).ToNot(HaveOccurred())
		Expect(os.WriteFile(path.Join(fileDir, "secret-file"), secretFileValue, 0600)).To(Succeed())
	})

	AfterEach(func() {
		os.Unsetenv(secretEnvKey)
		os.RemoveAll(fileDir)
	})

	It("returns the correct value from the string value", func() {
		value, err := GetSecretValue(&options.SecretSource{
			Value: []byte("secret-value-1"),
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(string(value)).To(Equal("secret-value-1"))
	})

	It("returns the correct value from the environment", func() {
		value, err := GetSecretValue(&options.SecretSource{
			FromEnv: secretEnvKey,
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(value).To(BeEquivalentTo(secretEnvValue))
	})

	It("returns the correct value from a file", func() {
		value, err := GetSecretValue(&options.SecretSource{
			FromFile: path.Join(fileDir, "secret-file"),
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(value).To(Equal(secretFileValue))
	})

	It("when the file does not exist", func() {
		value, err := GetSecretValue(&options.SecretSource{
			FromFile: path.Join(fileDir, "not-exist"),
		})
		Expect(err).To(HaveOccurred())
		Expect(value).To(BeEmpty())
	})

	It("with no source set", func() {
		value, err := GetSecretValue(&options.SecretSource{})
		Expect(err).To(MatchError("secret source is invalid: exactly one entry required, specify either value, fromEnv or fromFile"))
		Expect(value).To(BeEmpty())
	})

	It("with multiple sources set", func() {
		value, err := GetSecretValue(&options.SecretSource{
			FromEnv:  secretEnvKey,
			FromFile: path.Join(fileDir, "secret-file"),
		})
		Expect(err).To(MatchError("secret source is invalid: exactly one entry required, specify either value, fromEnv or fromFile"))
		Expect(value).To(BeEmpty())
	})
})
