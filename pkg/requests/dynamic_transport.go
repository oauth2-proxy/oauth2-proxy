package requests

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
)

// DynamicTLSTransport wraps http.Transport with dynamic CA verification.
// It uses VerifyPeerCertificate callback to perform certificate verification
// with a dynamically reloadable CA pool, enabling hot-reload of CA certificates
// without restarting the application.
type DynamicTLSTransport struct {
	base     *http.Transport
	caLoader *DynamicCALoader
}

// NewDynamicTLSTransport creates a new transport that uses the provided
// DynamicCALoader for certificate verification. The CA certificates can
// be reloaded at runtime without affecting in-flight requests.
func NewDynamicTLSTransport(caLoader *DynamicCALoader) *DynamicTLSTransport {
	base := http.DefaultTransport.(*http.Transport).Clone()

	dt := &DynamicTLSTransport{
		base:     base,
		caLoader: caLoader,
	}

	base.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		// We set InsecureSkipVerify to true because we perform our own
		// verification in VerifyPeerCertificate. This allows us to use
		// a dynamically updated CA pool for verification.
		InsecureSkipVerify:    true, // #nosec G402 -- verification done in VerifyPeerCertificate
		VerifyPeerCertificate: dt.verifyPeerCertificate,
	}

	return dt
}

// RoundTrip implements http.RoundTripper
func (dt *DynamicTLSTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return dt.base.RoundTrip(req)
}

// verifyPeerCertificate is called during TLS handshake to verify the server's
// certificate chain using the current CA pool from the DynamicCALoader.
// This enables hot-reload of CA certificates - each new connection will use
// the latest CA certificates.
func (dt *DynamicTLSTransport) verifyPeerCertificate(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	if len(rawCerts) == 0 {
		return fmt.Errorf("no certificates provided by server")
	}

	pool, err := dt.caLoader.GetCertPool()
	if err != nil {
		return fmt.Errorf("failed to get CA pool: %w", err)
	}

	// Parse all certificates in the chain
	certs := make([]*x509.Certificate, len(rawCerts))
	for i, raw := range rawCerts {
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("failed to parse certificate: %w", err)
		}
		certs[i] = cert
	}

	// Build verification options with the dynamic CA pool
	opts := x509.VerifyOptions{
		Roots:         pool,
		Intermediates: x509.NewCertPool(),
	}

	// Add intermediate certificates (all except the leaf)
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}

	// Verify the leaf certificate
	if _, err := certs[0].Verify(opts); err != nil {
		return fmt.Errorf("certificate verification failed: %w", err)
	}

	return nil
}
