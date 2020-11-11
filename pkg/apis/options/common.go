package options

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

// IsZero determines if the SecretSource is empty.
// Returns false if any field in the struct is not its zero value.
func (s SecretSource) IsZero() bool {
	return len(s.Value) == 0 && s.FromEnv == "" && s.FromFile == ""
}
