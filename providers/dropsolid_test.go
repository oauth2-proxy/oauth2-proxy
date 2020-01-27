package providers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/stretchr/testify/assert"
)

func testDropsolidProvider(hostname string) *DropsolidProvider {
	p := NewDropsolidProvider(
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

func testDropsolidBackend(payload string) *httptest.Server {
	path := "/oauth/user.info"

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != path {
				w.WriteHeader(404)
			} else if r.Header.Get("Authorization") != "Bearer imaginary_access_token" {
				w.WriteHeader(403)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			}
		}))
}

func TestDropsolidProviderDefaults(t *testing.T) {
	p := testDropsolidProvider("")
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Dropsolid", p.Data().ProviderName)
	assert.Equal(t, "https://platform.dropsolid.com/oauth/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://platform.dropsolid.com/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://platform.dropsolid.com/oauth/user.info",
		p.Data().ProfileURL.String())
	assert.Equal(t, "https://platform.dropsolid.com/oauth/user.info",
		p.Data().ValidateURL.String())
	assert.Equal(t, "openid email", p.Data().Scope)
}

func TestDropsolidProviderOverrides(t *testing.T) {
	p := NewDropsolidProvider(
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
	assert.Equal(t, "Dropsolid", p.Data().ProviderName)
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

func TestDropsolidProviderGetEmailAddress(t *testing.T) {
	b := testDropsolidBackend(`{"sub": "23", "email":"user@example.com"}`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testDropsolidProvider(bURL.Host)

	session := &sessions.SessionState{AccessToken: "imaginary_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "user@example.com", email)
}

func TestDropsolidProviderGetEmailAddressFailedRequest(t *testing.T) {
	b := testDropsolidBackend("unused payload")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testDropsolidProvider(bURL.Host)

	// We'll trigger a request failure by using an unexpected access
	// token. Alternatively, we could allow the parsing of the payload as
	// JSON to fail.
	session := &sessions.SessionState{AccessToken: "unexpected_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}

func TestDropsolidProviderGetEmailAddressEmailNotPresentInPayload(t *testing.T) {
	b := testDropsolidBackend("{\"foo\": \"bar\"}")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testDropsolidProvider(bURL.Host)

	session := &sessions.SessionState{AccessToken: "imaginary_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}
