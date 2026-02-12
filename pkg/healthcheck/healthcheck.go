package healthcheck

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	// DefaultHTTPAddress is the default bind address for the HTTP server.
	DefaultHTTPAddress = "127.0.0.1:4180"

	// DefaultPingPath is the default path for the ping endpoint.
	DefaultPingPath = "/ping"

	// DefaultTimeout is the default timeout for the health check request.
	DefaultTimeout = 5 * time.Second
)

// CheckOptions holds configuration for a health check request.
type CheckOptions struct {
	// HTTPAddress is the address the oauth2-proxy HTTP server is bound to.
	// Format: [http://]<addr>:<port>
	HTTPAddress string

	// HTTPSAddress is the address the oauth2-proxy HTTPS server is bound to.
	// Format: <addr>:<port>
	HTTPSAddress string

	// PingPath is the URL path for the ping endpoint.
	PingPath string

	// Timeout is the maximum duration for the health check request.
	Timeout time.Duration

	// InsecureSkipVerify skips TLS certificate verification for HTTPS checks.
	InsecureSkipVerify bool
}

// DefaultCheckOptions returns CheckOptions with sensible defaults.
func DefaultCheckOptions() CheckOptions {
	return CheckOptions{
		HTTPAddress:  DefaultHTTPAddress,
		HTTPSAddress: "",
		PingPath:     DefaultPingPath,
		Timeout:      DefaultTimeout,
	}
}

// Run performs the health check and returns nil on success or an error on failure.
// It checks the HTTP address first. If the HTTP address is empty or disabled,
// it falls back to the HTTPS address.
func Run(opts CheckOptions) error {
	if opts.PingPath == "" {
		opts.PingPath = DefaultPingPath
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultTimeout
	}

	httpAddr := normalizeAddress(opts.HTTPAddress)
	httpsAddr := normalizeAddress(opts.HTTPSAddress)

	// Try HTTP first, then HTTPS
	if httpAddr != "" && httpAddr != "-" {
		return checkEndpoint("http", httpAddr, opts.PingPath, opts.Timeout, opts.InsecureSkipVerify)
	}

	if httpsAddr != "" && httpsAddr != "-" {
		return checkEndpoint("https", httpsAddr, opts.PingPath, opts.Timeout, opts.InsecureSkipVerify)
	}

	return fmt.Errorf("no bind address configured; cannot perform health check")
}

// normalizeAddress strips an optional scheme prefix and returns the host:port.
func normalizeAddress(addr string) string {
	addr = strings.TrimSpace(addr)
	// Strip optional scheme prefix (e.g., "http://127.0.0.1:4180")
	for _, prefix := range []string{"http://", "https://"} {
		if strings.HasPrefix(strings.ToLower(addr), prefix) {
			addr = addr[len(prefix):]
			break
		}
	}
	return addr
}

// checkEndpoint performs a GET request against scheme://addr/pingPath and validates
// that the response status is 200 OK.
func checkEndpoint(scheme, addr, pingPath string, timeout time.Duration, insecureSkipVerify bool) error {
	// Replace unspecified addresses with loopback so the check connects locally.
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid address %q: %v", addr, err)
	}

	host = replaceUnspecified(host)
	target := net.JoinHostPort(host, port)

	url := fmt.Sprintf("%s://%s%s", scheme, target, pingPath)

	client := &http.Client{
		Timeout: timeout,
		// Do not follow redirects; we expect a direct 200 from the ping endpoint.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if scheme == "https" {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: insecureSkipVerify, //nolint:gosec // intentional for local health check against self-signed certs
			},
		}
	}

	resp, err := client.Get(url) //nolint:gosec // URL is constructed from known configuration, not user input
	if err != nil {
		return fmt.Errorf("health check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return fmt.Errorf("health check returned status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// replaceUnspecified replaces unspecified (wildcard) addresses with their
// loopback equivalents so the health check connects locally.
func replaceUnspecified(host string) string {
	switch host {
	case "", "0.0.0.0":
		return "127.0.0.1"
	case "::", "[::]":
		return "::1"
	}
	// Strip brackets from IPv6 addresses that net.SplitHostPort already handled
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip != nil && ip.IsUnspecified() {
		if ip.To4() != nil {
			return "127.0.0.1"
		}
		return "::1"
	}
	return host
}
