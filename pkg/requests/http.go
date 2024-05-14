package requests

import (
	"net/http"

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

var DefaultHTTPClient = &http.Client{Transport: &userAgentTransport{
	next:      http.DefaultTransport,
	userAgent: "oauth2-proxy/" + version.VERSION,
}}

func setDefaultUserAgent(header http.Header, userAgent string) {
	if header != nil && len(header.Values("User-Agent")) == 0 {
		header.Set("User-Agent", userAgent)
	}
}
