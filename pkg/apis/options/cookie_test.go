package options

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCookieGetSecret(t *testing.T) {
	t.Run("returns secret when Secret is set", func(t *testing.T) {
		c := &Cookie{
			Secret:     "my-secret",
			SecretFile: "",
		}
		secret, err := c.GetSecret()
		assert.NoError(t, err)
		assert.Equal(t, "my-secret", secret)
	})

	t.Run("returns secret when both Secret and SecretFile are set", func(t *testing.T) {
		c := &Cookie{
			Secret:     "my-secret",
			SecretFile: "/some/file",
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
			Secret:     "",
			SecretFile: tmpfile.Name(),
		}
		secret, err := c.GetSecret()
		assert.NoError(t, err)
		assert.Equal(t, "file-secret", secret)
	})

	t.Run("returns error when file does not exist", func(t *testing.T) {
		c := &Cookie{
			Secret:     "",
			SecretFile: "/nonexistent/file",
		}
		secret, err := c.GetSecret()
		assert.Error(t, err)
		assert.Equal(t, "", secret)
		assert.Contains(t, err.Error(), "could not read cookie secret file")
	})

	t.Run("returns empty when both Secret and SecretFile are empty", func(t *testing.T) {
		c := &Cookie{
			Secret:     "",
			SecretFile: "",
		}
		secret, err := c.GetSecret()
		assert.NoError(t, err)
		assert.Equal(t, "", secret)
	})
}

func TestCookiePartitionedOptionLoading(t *testing.T) {
	tests := []struct {
		name     string
		config   string
		env      string
		args     []string
		expected bool
	}{
		{
			name:     "default",
			expected: false,
		},
		{
			name:     "config file",
			config:   "cookie_partitioned = true\n",
			expected: true,
		},
		{
			name:     "environment variable",
			env:      "true",
			expected: true,
		},
		{
			name:     "command line flag",
			env:      "false",
			args:     []string{"--cookie-partitioned"},
			expected: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OAUTH2_PROXY_COOKIE_PARTITIONED", tc.env)

			configFile := ""
			if tc.config != "" {
				configFile = t.TempDir() + "/oauth2-proxy.cfg"
				if !assert.NoError(t, os.WriteFile(configFile, []byte(tc.config), 0600)) {
					return
				}
			}

			flagSet := NewFlagSet()
			if !assert.NoError(t, flagSet.Parse(tc.args)) {
				return
			}

			opts := NewOptions()
			if !assert.NoError(t, Load(configFile, flagSet, opts)) {
				return
			}
			assert.Equal(t, tc.expected, opts.Cookie.Partitioned)
		})
	}
}
