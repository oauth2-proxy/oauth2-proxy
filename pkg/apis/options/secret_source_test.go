package options

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	testSecretValue       = "bXktc2VjcmV0" // base64 for "my-secret"
	testFileSecretContent = "file-secret"
)

func TestSecretSourceGetSecretValue(t *testing.T) {
	t.Run("returns secret when Value is set", func(t *testing.T) {
		ss := &SecretSource{
			Value:    []byte(testSecretValue),
			FromFile: "",
		}
		secret, err := ss.GetSecretValue()
		assert.NoError(t, err)
		assert.Equal(t, "my-secret", string(secret))
	})

	t.Run("returns secret when both Value and FromFile are set", func(t *testing.T) {
		ss := &SecretSource{
			Value:    []byte(testSecretValue),
			FromFile: "/some/file",
		}
		secret, err := ss.GetSecretValue()
		assert.NoError(t, err)
		assert.Equal(t, "my-secret", string(secret))
	})

	t.Run("reads from file when only FromFile is set", func(t *testing.T) {
		// Create a temporary file
		tmpfile, err := os.CreateTemp("", "secret-source-test")
		assert.NoError(t, err)
		defer os.Remove(tmpfile.Name())

		_, err = tmpfile.Write([]byte(testFileSecretContent))
		assert.NoError(t, err)
		tmpfile.Close()

		ss := &SecretSource{
			FromFile: tmpfile.Name(),
		}
		secret, err := ss.GetSecretValue()
		assert.NoError(t, err)
		assert.Equal(t, "file-secret", string(secret))
	})

	t.Run("returns error when file does not exist", func(t *testing.T) {
		ss := &SecretSource{
			FromFile: "/nonexistent/file",
		}
		secret, err := ss.GetSecretValue()
		assert.Error(t, err)
		assert.Nil(t, secret)
	})

	t.Run("returns error when no source is defined", func(t *testing.T) {
		ss := &SecretSource{}
		secret, err := ss.GetSecretValue()
		assert.Error(t, err)
		assert.Nil(t, secret)
	})

	t.Run("returns error when Value is not valid base64", func(t *testing.T) {
		ss := &SecretSource{
			Value:    []byte("invalid-base64"),
			FromFile: "",
		}
		secret, err := ss.GetSecretValue()
		assert.Error(t, err)
		assert.Nil(t, secret)
	})
}
