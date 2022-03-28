package options

// Server represents the configuration for an HTTP(S) server
type Server struct {
	// BindAddress is the address on which to serve traffic.
	// Leave blank or set to "-" to disable.
	BindAddress string

	// SecureBindAddress is the address on which to serve secure traffic.
	// Leave blank or set to "-" to disable.
	SecureBindAddress string

	// TLS contains the information for loading the certificate and key for the
	// secure traffic and further configuration for the TLS server.
	TLS *TLS
}

// TLS contains the information for loading a TLS certificate and key
// as well as an optional minimal TLS version that is acceptable.
type TLS struct {
	// Key is the TLS key data to use.
	// Typically this will come from a file.
	Key *SecretSource

	// Cert is the TLS certificate data to use.
	// Typically this will come from a file.
	Cert *SecretSource

	// MinVersion is the minimal TLS version that is acceptable.
	// E.g. Set to "TLS1.3" to select TLS version 1.3
	MinVersion string
}
