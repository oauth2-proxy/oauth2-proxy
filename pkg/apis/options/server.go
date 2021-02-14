package options

// Server represents the configuration for an HTTP(S) server
type Server struct {
	// BindAddress is the the address on which to serve traffic.
	// Leave blank or set to "-" to disable.
	BindAddress string

	// SecureBindAddress is the the address on which to serve secure traffic.
	// Leave blank or set to "-" to disable.
	SecureBindAddress string

	// TLS contains the information for loading the certificate and key for the
	// secure traffic.
	TLS *TLS
}

// TLS contains the information for loading a TLS certifcate and key.
type TLS struct {
	// Key is the the TLS key data to use.
	// Typically this will come from a file.
	Key *SecretSource

	// Cert is the TLS certificate data to use.
	// Typically this will come from a file.
	Cert *SecretSource
}
