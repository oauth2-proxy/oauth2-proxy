package options

// Server represents the configuration for an HTTP(S) server
type Server struct {
	// BindAddress is the address on which to serve traffic.
	// Leave blank or set to "-" to disable.
	BindAddress string `yaml:"bindAddress,omitempty"`

	// SecureBindAddress is the address on which to serve secure traffic.
	// Leave blank or set to "-" to disable.
	SecureBindAddress string `yaml:"secureBindAddress,omitempty"`

	// TLS contains the information for loading the certificate and key for the
	// secure traffic and further configuration for the TLS server.
	TLS *TLS `yaml:"tls,omitempty"`
}

// TLS contains the information for loading a TLS certificate and key
// as well as an optional minimal TLS version that is acceptable.
type TLS struct {
	// Key is the TLS key data to use.
	// Typically this will come from a file.
	Key *SecretSource `yaml:"key,omitempty"`

	// Cert is the TLS certificate data to use.
	// Typically this will come from a file.
	Cert *SecretSource `yaml:"cert,omitempty"`

	// MinVersion is the minimal TLS version that is acceptable.
	// E.g. Set to "TLS1.3" to select TLS version 1.3
	MinVersion string `yaml:"minVersion,omitempty"`

	// CipherSuites is a list of TLS cipher suites that are allowed.
	// E.g.:
	// - TLS_RSA_WITH_RC4_128_SHA
	// - TLS_RSA_WITH_AES_256_GCM_SHA384
	// If not specified, the default Go safe cipher list is used.
	// List of valid cipher suites can be found in the [crypto/tls documentation](https://pkg.go.dev/crypto/tls#pkg-constants).
	CipherSuites []string `yaml:"cipherSuites,omitempty"`
}
