package options

import "github.com/spf13/pflag"

type LegacyServer struct {
	MetricsAddress       string   `flag:"metrics-address" cfg:"metrics_address"`
	MetricsSecureAddress string   `flag:"metrics-secure-address" cfg:"metrics_secure_address"`
	MetricsTLSCertFile   string   `flag:"metrics-tls-cert-file" cfg:"metrics_tls_cert_file"`
	MetricsTLSKeyFile    string   `flag:"metrics-tls-key-file" cfg:"metrics_tls_key_file"`
	HTTPAddress          string   `flag:"http-address" cfg:"http_address"`
	HTTPSAddress         string   `flag:"https-address" cfg:"https_address"`
	TLSCertFile          string   `flag:"tls-cert-file" cfg:"tls_cert_file"`
	TLSKeyFile           string   `flag:"tls-key-file" cfg:"tls_key_file"`
	TLSMinVersion        string   `flag:"tls-min-version" cfg:"tls_min_version"`
	TLSCipherSuites      []string `flag:"tls-cipher-suite" cfg:"tls_cipher_suites"`
}

func legacyServerFlagset() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("server", pflag.ExitOnError)

	flagSet.String("metrics-address", "", "the address /metrics will be served on (e.g. \":9100\")")
	flagSet.String("metrics-secure-address", "", "the address /metrics will be served on for HTTPS clients (e.g. \":9100\")")
	flagSet.String("metrics-tls-cert-file", "", "path to certificate file for secure metrics server")
	flagSet.String("metrics-tls-key-file", "", "path to private key file for secure metrics server")
	flagSet.String("http-address", "127.0.0.1:4180", "[http://]<addr>:<port> or unix://<path> to listen on for HTTP clients")
	flagSet.String("https-address", ":443", "<addr>:<port> to listen on for HTTPS clients")
	flagSet.String("tls-cert-file", "", "path to certificate file")
	flagSet.String("tls-key-file", "", "path to private key file")
	flagSet.String("tls-min-version", "", "minimal TLS version for HTTPS clients (either \"TLS1.2\" or \"TLS1.3\")")
	flagSet.StringSlice("tls-cipher-suite", []string{}, "restricts TLS cipher suites to those listed (e.g. TLS_RSA_WITH_RC4_128_SHA) (may be given multiple times)")

	return flagSet
}

func (l LegacyServer) convert() (Server, Server) {
	appServer := Server{
		BindAddress:       l.HTTPAddress,
		SecureBindAddress: l.HTTPSAddress,
	}
	if l.TLSKeyFile != "" || l.TLSCertFile != "" {
		appServer.TLS = &TLS{
			Key: &SecretSource{
				FromFile: l.TLSKeyFile,
			},
			Cert: &SecretSource{
				FromFile: l.TLSCertFile,
			},
			MinVersion: l.TLSMinVersion,
		}
		if len(l.TLSCipherSuites) != 0 {
			appServer.TLS.CipherSuites = l.TLSCipherSuites
		}
		// Preserve backwards compatibility, only run one server
		appServer.BindAddress = ""
	} else {
		// Disable the HTTPS server if there's no certificates.
		// This preserves backwards compatibility.
		appServer.SecureBindAddress = ""
	}

	metricsServer := Server{
		BindAddress:       l.MetricsAddress,
		SecureBindAddress: l.MetricsSecureAddress,
	}
	if l.MetricsTLSKeyFile != "" || l.MetricsTLSCertFile != "" {
		metricsServer.TLS = &TLS{
			Key: &SecretSource{
				FromFile: l.MetricsTLSKeyFile,
			},
			Cert: &SecretSource{
				FromFile: l.MetricsTLSCertFile,
			},
		}
	}

	return appServer, metricsServer
}
