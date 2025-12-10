package options

import (
	"encoding/base64"
	"fmt"
	"os"
)

// SecretSource references an individual secret value.
// Only one source within the struct should be defined at any time.
type SecretSource struct {
	// Value expects a base64 encoded string value.
	Value []byte `yaml:"value,omitempty"`

	// FromEnv expects the name of an environment variable.
	FromEnv string `yaml:"fromEnv,omitempty"`

	// FromFile expects a path to a file containing the secret value.
	FromFile string `yaml:"fromFile,omitempty"`
}

func NewSecretSourceFromValue(value []byte) *SecretSource {
	encoded := make([]byte, base64.RawStdEncoding.EncodedLen(len(value)))
	base64.RawStdEncoding.Encode(encoded, value)
	return &SecretSource{
		Value: encoded,
	}
}

func NewSecretSourceFromString(s string) *SecretSource {
	return NewSecretSourceFromValue([]byte(s))
}

func (ss *SecretSource) GetSecretValue() ([]byte, error) {
	if len(ss.Value) > 0 {
		var decoded []byte
		if _, err := base64.RawStdEncoding.Decode(decoded, ss.Value); err != nil {
			return nil, fmt.Errorf("error decoding secret value: %w", err)
		}
		return decoded, nil
	}

	if ss.FromEnv != "" {
		envValue := os.Getenv(ss.FromEnv)
		return []byte(envValue), nil
	}

	if ss.FromFile != "" {
		fileData, err := os.ReadFile(ss.FromFile)
		if err != nil {
			return nil, fmt.Errorf("error reading secret from file %q: %w", ss.FromFile, err)
		}
		return fileData, nil
	}

	return nil, nil
}

// EnsureDefaults sets any default values for SecretSource fields.
func (ss *SecretSource) EnsureDefaults() {
	// No defaults to set currently
}
