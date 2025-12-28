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
	encoded := make([]byte, base64.URLEncoding.EncodedLen(len(value)))
	base64.URLEncoding.Encode(encoded, value)
	return &SecretSource{
		Value: encoded,
	}
}

func NewSecretSourceFromString(s string) *SecretSource {
	return NewSecretSourceFromValue([]byte(s))
}

func (ss *SecretSource) GetRawSecretValue() ([]byte, error) {
	if len(ss.Value) > 0 {
		return ss.Value, nil
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

func (ss *SecretSource) GetSecretValue() ([]byte, error) {
	value, err := ss.GetRawSecretValue()
	if err != nil {
		return nil, fmt.Errorf("failed getting raw secret value: %w", err)
	}

	if value == nil {
		return nil, fmt.Errorf("failed retrieving secret value: no source defined")
	}

	if len(ss.Value) == 0 && ss.FromFile != "" {
		return value, nil
	}

	decoded := make([]byte, base64.URLEncoding.DecodedLen(len(value)))
	if _, err := base64.URLEncoding.Decode(decoded, value); err != nil {
		return nil, fmt.Errorf("error decoding secret value: %w", err)
	}
	return decoded, nil
}

// MarshalYAML implements the yaml.Marshaler interface for SecretSource.
// This is only necessary for the conversion workflow from toml to yaml
func (ss *SecretSource) MarshalYAML() (interface{}, error) {
	if ss == nil {
		return nil, nil
	}

	if ss.FromFile != "" {
		return map[string]string{
			"fromFile": ss.FromFile,
		}, nil
	}

	encodedValue, err := ss.GetRawSecretValue()
	if err != nil {
		return nil, fmt.Errorf("error getting raw secret value for marshaling: %w", err)
	}

	return map[string]string{
		"value": string(encodedValue),
	}, nil
}

// EnsureDefaults sets any default values for SecretSource fields.
func (ss *SecretSource) EnsureDefaults() {
	// No defaults to set currently
}
