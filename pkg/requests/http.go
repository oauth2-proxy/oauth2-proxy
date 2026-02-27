package requests

import (
	"net/http"
	"sync/atomic"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/version"
)

type userAgentTransport struct {
	next      http.RoundTripper
	userAgent string
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	setDefaultUserAgent(r.Header, t.userAgent)
	return t.next.RoundTrip(r)
}

// defaultTransport holds a pointer to the current transport (can be swapped atomically)
var defaultTransport atomic.Pointer[http.RoundTripper]

// transportProxy implements http.RoundTripper and delegates to the atomic pointer.
// This allows the underlying transport to be swapped at runtime for CA reload.
type transportProxy struct{}

func (t *transportProxy) RoundTrip(req *http.Request) (*http.Response, error) {
	transport := defaultTransport.Load()
	if transport == nil {
		return http.DefaultTransport.RoundTrip(req)
	}
	return (*transport).RoundTrip(req)
}

// DefaultHTTPClient is the shared HTTP client used for provider requests.
// It uses a transport proxy that supports runtime transport swapping for CA reload.
var DefaultHTTPClient = &http.Client{Transport: &userAgentTransport{
	next:      &transportProxy{},
	userAgent: "oauth2-proxy/" + version.VERSION,
}}

// DefaultTransport is kept for backward compatibility.
// New code should use SetDefaultTransport to update the transport.
var DefaultTransport = http.DefaultTransport

// SetDefaultTransport atomically sets the default transport used by DefaultHTTPClient.
// This is used to enable dynamic CA certificate reloading.
func SetDefaultTransport(rt http.RoundTripper) {
	defaultTransport.Store(&rt)
	// Also update the legacy variable for backward compatibility with existing code
	DefaultTransport = rt
}

func setDefaultUserAgent(header http.Header, userAgent string) {
	if header != nil && len(header.Values("User-Agent")) == 0 {
		header.Set("User-Agent", userAgent)
	}
}
