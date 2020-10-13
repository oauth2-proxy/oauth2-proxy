package util

import (
	"encoding/base64"
	"io/ioutil"
	"os"
	"path"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	. "github.com/onsi/ginkgo"
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
		fileDir, err = ioutil.TempDir("", "oauth2-proxy-util-get-secret-value")
		Expect(err).ToNot(HaveOccurred())
		Expect(ioutil.WriteFile(path.Join(fileDir, "secret-file"), secretFileValue, 0600)).To(Succeed())
	})

	AfterEach(func() {
		os.Unsetenv(secretEnvKey)
		os.RemoveAll(fileDir)
	})

	It("returns the correct value from base64", func() {
		originalValue := []byte("secret-value-1")
		b64Value := base64.StdEncoding.EncodeToString((originalValue))

		// Once encoded, the originalValue could have a decoded length longer than
		// its actual length, ensure we trim this.
		// This assertion ensures we are testing the triming
		Expect(len(originalValue)).To(BeNumerically("<", base64.StdEncoding.DecodedLen(len(b64Value))))

		value, err := GetSecretValue(&options.SecretSource{
			Value: []byte(b64Value),
		})
		Expect(err).ToNot(HaveOccurred())
		Expect(value).To(Equal(originalValue))
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
