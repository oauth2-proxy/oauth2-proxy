package providers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func testGlobusProvider(hostname string) *GlobusProvider {
	p := NewGlobusProvider(
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
		updateURL(p.Data().ValidateURL, hostname)
	}
	return p
}

func testGlobusBackend(payload string) *httptest.Server {
	path := "/v2/oauth2/userinfo"
	header := "Bearer imaginary_access_token"

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			url := r.URL
			if url.Path != path  || header != r.Header.Get("Authorization") {
				w.WriteHeader(404)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			}
		}))
}

func TestGlobusProviderDefaults(t *testing.T) {
	p := testGlobusProvider("")
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Globus", p.Data().ProviderName)
	assert.Equal(t, "https://auth.globus.org/v2/oauth2/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://auth.globus.org/v2/oauth2/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://auth.globus.org/v2/oauth2/token/introspect",
		p.Data().ValidateURL.String())
	assert.Equal(t, "openid email profile", p.Data().Scope)
}

func TestGlobusProviderOverrides(t *testing.T) {
	p := NewGlobusProvider(
		&ProviderData{
			LoginURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/auth"},
			RedeemURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/token"},
			ValidateURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/api/v4/user"},
			Scope: "profile"})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Globus", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/oauth/auth",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://example.com/api/v4/user",
		p.Data().ValidateURL.String())
	assert.Equal(t, "profile", p.Data().Scope)
}

func TestGlobusProviderGetEmailAddress(t *testing.T) {
	//b := testGlobusBackend("{\"email\": \"michael.bland@gsa.gov\"}")
	b := testGlobusBackend("{ \"email\": \"ztaylor@example.com\", \"name\": \"Zachary Taylor\", \"preferred_username\": \"ztaylor@globusid.org\", \"sub\": \"e9a5903a-cb98-11e5-a7fa-afe061bd0f40\" }")
	defer b.Close()

	b_url, _ := url.Parse(b.URL)
	p := testGlobusProvider(b_url.Host)

	session := &SessionState{AccessToken: "imaginary_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "ztaylor@example.com", email)
}
