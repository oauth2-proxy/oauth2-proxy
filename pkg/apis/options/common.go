package options

import (
	"fmt"
	"strings"
	"time"
)

// SecretSource references an individual secret value.
// Only one source within the struct should be defined at any time.
type SecretSource struct {
	// Value expects a base64 encoded string value.
	Value []byte

	// FromEnv expects the name of an environment variable.
	FromEnv string

	// FromFile expects a path to a file containing the secret value.
	FromFile string
}

type Duration time.Duration

func (d *Duration) UnmarshalJSON(data []byte) error {
	input := string(data)
	input = strings.TrimPrefix(input, "\"")
	input = strings.TrimSuffix(input, "\"")
	du, err := time.ParseDuration(input)
	if err != nil {
		return err
	}
	*d = Duration(du)
	return nil
}

func (d *Duration) MarshalJSON() ([]byte, error) {
	dStr := fmt.Sprintf("%q", d.Duration().String())
	return []byte(dStr), nil
}

func (d *Duration) Duration() time.Duration {
	if d == nil {
		return time.Duration(0)
	}
	return time.Duration(*d)
}
