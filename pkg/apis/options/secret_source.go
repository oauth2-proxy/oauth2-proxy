package options

// SecretSource references an individual secret value.
// Only one source within the struct should be defined at any time.
type SecretSource struct {
	// Value expects a base64 encoded string value.
	Value string `json:"value,omitempty"`

	// FromEnv expects the name of an environment variable.
	FromEnv string `json:"fromEnv,omitempty"`

	// FromFile expects a path to a file containing the secret value.
	FromFile string `json:"fromFile,omitempty"`
}
