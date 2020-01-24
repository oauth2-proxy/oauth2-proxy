package providers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/stretchr/testify/assert"
)

func testDigitalOceanProvider(hostname string) *DigitalOceanProvider {
	p := NewDigitalOceanProvider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""})
	if hostname != "" {
		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		updateURL(p.Data().ProfileURL, hostname)
	}
	return p
}

func testDigitalOceanBackend(payload string) *httptest.Server {
	path := "/v2/account"

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != path {
				w.WriteHeader(404)
			} else if !IsAuthorizedInHeader(r.Header) {
				w.WriteHeader(403)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			}
		}))
}

func TestDigitalOceanProviderDefaults(t *testing.T) {
	p := testDigitalOceanProvider("")
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "DigitalOcean", p.Data().ProviderName)
	assert.Equal(t, "https://cloud.digitalocean.com/v1/oauth/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://cloud.digitalocean.com/v1/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://api.digitalocean.com/v2/account",
		p.Data().ProfileURL.String())
	assert.Equal(t, "https://api.digitalocean.com/v2/account",
		p.Data().ValidateURL.String())
	assert.Equal(t, "read", p.Data().Scope)
}

func TestDigitalOceanProviderOverrides(t *testing.T) {
	p := NewDigitalOceanProvider(
		&ProviderData{
			LoginURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/auth"},
			RedeemURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/token"},
			ProfileURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/profile"},
			ValidateURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/tokeninfo"},
			Scope: "profile"})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "DigitalOcean", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/oauth/auth",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://example.com/oauth/profile",
		p.Data().ProfileURL.String())
	assert.Equal(t, "https://example.com/oauth/tokeninfo",
		p.Data().ValidateURL.String())
	assert.Equal(t, "profile", p.Data().Scope)
}

func TestDigitalOceanProviderGetEmailAddress(t *testing.T) {
	b := testDigitalOceanBackend(`{"account": {"email": "user@example.com"}}`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testDigitalOceanProvider(bURL.Host)

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "user@example.com", email)
}

func TestDigitalOceanProviderGetEmailAddressFailedRequest(t *testing.T) {
	b := testDigitalOceanBackend("unused payload")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testDigitalOceanProvider(bURL.Host)

	// We'll trigger a request failure by using an unexpected access
	// token. Alternatively, we could allow the parsing of the payload as
	// JSON to fail.
	session := &sessions.SessionState{AccessToken: "unexpected_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}

func TestDigitalOceanProviderGetEmailAddressEmailNotPresentInPayload(t *testing.T) {
	b := testDigitalOceanBackend("{\"foo\": \"bar\"}")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testDigitalOceanProvider(bURL.Host)

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}
