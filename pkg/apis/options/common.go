package options

import (
	"fmt"
	"strconv"
	"time"
)

// SecretSource references an individual secret value.
// Only one source within the struct should be defined at any time.
type SecretSource struct {
	// Value expects a base64 encoded string value.
	Value []byte `json:"value,omitempty"`

	// FromEnv expects the name of an environment variable.
	FromEnv string `json:"fromEnv,omitempty"`

	// FromFile expects a path to a file containing the secret value.
	FromFile string `json:"fromFile,omitempty"`
}

// Duration is an alias for time.Duration so that we can ensure the marshalling
// and unmarshalling of string durations is done as users expect.
// Intentional blank line below to keep this first part of the comment out of
// any generated references.

// Duration is as string representation of a period of time.
// A duration string is a is a possibly signed sequence of decimal numbers,
// each with optional fraction and a unit suffix, such as "300ms", "-1.5h" or "2h45m".
// Valid time units are "ns", "us" (or "µs"), "ms", "s", "m", "h".
type Duration time.Duration

// UnmarshalJSON parses the duration string and sets the value of duration
// to the value of the duration string.
func (d *Duration) UnmarshalJSON(data []byte) error {
	input := string(data)
	if unquoted, err := strconv.Unquote(input); err == nil {
		input = unquoted
	}

	du, err := time.ParseDuration(input)
	if err != nil {
		return err
	}
	*d = Duration(du)
	return nil
}

// MarshalJSON ensures that when the string is marshalled to JSON as a human
// readable string.
func (d *Duration) MarshalJSON() ([]byte, error) {
	dStr := fmt.Sprintf("%q", d.Duration().String())
	return []byte(dStr), nil
}

// Duration returns the time.Duration version of this Duration
func (d *Duration) Duration() time.Duration {
	if d == nil {
		return time.Duration(0)
	}
	return time.Duration(*d)
}
