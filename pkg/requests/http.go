package requests

import (
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg"
)

type userAgentTransport struct {
	next      http.RoundTripper
	userAgent string
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r2 := req.Clone(req.Context())
	setDefaultUserAgent(r2.Header, t.userAgent)
	return t.next.RoundTrip(r2)
}

var DefaultHttpClient = &http.Client{Transport: &userAgentTransport{
	http.DefaultTransport,
	"oauth2-proxy/" + pkg.VERSION,
}}

func setDefaultUserAgent(header http.Header, userAgent string) {
	if header != nil && len(header.Values("User-Agent")) == 0 {
		header.Set("User-Agent", userAgent)
	}
}
