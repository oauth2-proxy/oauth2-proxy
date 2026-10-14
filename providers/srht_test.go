package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func testSourceHutProvider(hostname string) *SourceHutProvider {
	p := NewSourceHutProvider(
		&ProviderData{
			ProviderName: "SourceHut",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""},
	)
	p.ProviderName = "SourceHut"

	if hostname != "" {
		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		updateURL(p.Data().ProfileURL, hostname)
		updateURL(p.Data().ValidateURL, hostname)
	}
	return p
}

func testSourceHutBackend(payloads map[string][]string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			index := 0
			payload, ok := payloads[r.URL.Path]
			if !ok {
				w.WriteHeader(404)
			} else if payload[index] == "" {
				w.WriteHeader(204)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload[index]))
			}
		}))
}

func TestSourceHutProvider_ValidateSessionWithBaseUrl(t *testing.T) {
	b := testSourceHutBackend(map[string][]string{})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testSourceHutProvider(bURL.Host)

	session := CreateAuthorizedSession()

	valid := p.ValidateSession(context.Background(), session)
	assert.False(t, valid)
}

func TestSourceHutProvider_ValidateSessionWithUserEmails(t *testing.T) {
	b := testSourceHutBackend(map[string][]string{
		"/query":   {`{"data":{"me":{"username":"bitfehler","email":"ch@bitfehler.net"}}}`},
		"/profile": {`ok`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testSourceHutProvider(bURL.Host)

	session := CreateAuthorizedSession()

	valid := p.ValidateSession(context.Background(), session)
	assert.True(t, valid)
}
