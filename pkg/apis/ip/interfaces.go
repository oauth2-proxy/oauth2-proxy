package ip

import (
	"net"
	"net/http"
)

// TrustedProxies reports whether a given IP belongs to a proxy that is
// trusted to supply forwarded headers.
type TrustedProxies interface {
	Has(net.IP) bool
}

// RealClientIPParser is an interface for a getting the client's real IP to be used for logging.
type RealClientIPParser interface {
	// GetRealClientIP parses the configured forwarded-header out of h. remoteAddr is the
	// IP of the direct connecting peer (nil if unknown) and trusted is the set of proxies
	// allowed to supply forwarded headers (nil if no trusted-proxy restriction is configured).
	GetRealClientIP(h http.Header, remoteAddr net.IP, trusted TrustedProxies) (net.IP, error)
}
