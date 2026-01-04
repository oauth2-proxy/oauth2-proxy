package options

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCookieGetSecret(t *testing.T) {
	t.Run("returns secret when Secret is set", func(t *testing.T) {
		c := &Cookie{
			Secret: &SecretSource{
				Value:    []byte("my-secret"),
				FromFile: "",
			},
		}
		secret, err := c.GetSecret()
		assert.NoError(t, err)
		assert.Equal(t, "my-secret", secret)
	})

	t.Run("returns secret when both Secret and SecretFile are set", func(t *testing.T) {
		c := &Cookie{
			Secret: &SecretSource{
				Value:    []byte("my-secret"),
				FromFile: "/some/file",
			},
		}
		secret, err := c.GetSecret()
		assert.NoError(t, err)
		assert.Equal(t, "my-secret", secret)
	})

	t.Run("reads from file when only SecretFile is set", func(t *testing.T) {
		// Create a temporary file
		tmpfile, err := os.CreateTemp("", "cookie-secret-test")
		assert.NoError(t, err)
		defer os.Remove(tmpfile.Name())

		_, err = tmpfile.Write([]byte("file-secret"))
		assert.NoError(t, err)
		tmpfile.Close()

		c := &Cookie{
			Secret: &SecretSource{
				Value:    []byte(""),
				FromFile: tmpfile.Name(),
			},
		}
		secret, err := c.GetSecret()
		assert.NoError(t, err)
		assert.Equal(t, "file-secret", secret)
	})

	t.Run("returns error when file does not exist", func(t *testing.T) {
		c := &Cookie{
			Secret: &SecretSource{
				Value:    []byte(""),
				FromFile: "/nonexistent/file",
			},
		}
		secret, err := c.GetSecret()
		assert.Error(t, err)
		assert.Equal(t, "", secret)
		assert.Contains(t, err.Error(), "error getting cookie secret: error reading secret from file \"/nonexistent/file\": open /nonexistent/file: no such file or directory")
	})

	t.Run("returns empty when both Secret and SecretFile are empty", func(t *testing.T) {
		c := &Cookie{
			Secret: &SecretSource{
				Value:    []byte(""),
				FromFile: "",
			},
		}
		secret, err := c.GetSecret()
		assert.NoError(t, err)
		assert.Equal(t, "", secret)
	})
}
