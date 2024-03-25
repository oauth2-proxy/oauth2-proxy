package requests

import (
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg"
)

type userAgentTransport struct {
}

func (t *userAgentTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r2 := req.Clone(req.Context())
	setDefaultUserAgent(r2.Header)
	return http.DefaultTransport.RoundTrip(r2)
}

var DefaultHttpClient = &http.Client{Transport: &userAgentTransport{}}

func setDefaultUserAgent(header http.Header) {
	if header != nil && len(header.Values("User-Agent")) == 0 {
		header.Set("User-Agent", "oauth2-proxy/"+pkg.VERSION)
	}
}
