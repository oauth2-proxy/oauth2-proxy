package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

func testKeycloakProvider(hostname, group string) *KeycloakProvider {
	p := NewKeycloakProvider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""})

	if group != "" {
		p.SetGroup(group)
	}

	if hostname != "" {
		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		updateURL(p.Data().ProfileURL, hostname)
		updateURL(p.Data().ValidateURL, hostname)
	}
	return p
}

func testKeycloakBackend(payload string) *httptest.Server {
	path := "/api/v3/user"

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			url := r.URL
			if url.Path != path {
				w.WriteHeader(404)
			} else if !IsAuthorizedInHeader(r.Header) {
				w.WriteHeader(403)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			}
		}))
}

func TestKeycloakProviderDefaults(t *testing.T) {
	p := testKeycloakProvider("", "")
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Keycloak", p.Data().ProviderName)
	assert.Equal(t, "https://keycloak.org/oauth/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://keycloak.org/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://keycloak.org/api/v3/user",
		p.Data().ValidateURL.String())
	assert.Equal(t, "api", p.Data().Scope)
}

func TestNewKeycloakProvider(t *testing.T) {
	g := NewWithT(t)

	// Test that defaults are set when calling for a new provider with nothing set
	providerData := NewKeycloakProvider(&ProviderData{}).Data()
	g.Expect(providerData.ProviderName).To(Equal("Keycloak"))
	g.Expect(providerData.LoginURL.String()).To(Equal("https://keycloak.org/oauth/authorize"))
	g.Expect(providerData.RedeemURL.String()).To(Equal("https://keycloak.org/oauth/token"))
	g.Expect(providerData.ProfileURL.String()).To(Equal(""))
	g.Expect(providerData.ValidateURL.String()).To(Equal("https://keycloak.org/api/v3/user"))
	g.Expect(providerData.Scope).To(Equal("api"))
}

func TestKeycloakProviderOverrides(t *testing.T) {
	p := NewKeycloakProvider(
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
				Path:   "/api/v3/user"},
			Scope: "profile"})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Keycloak", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/oauth/auth",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://example.com/api/v3/user",
		p.Data().ValidateURL.String())
	assert.Equal(t, "profile", p.Data().Scope)
}

func TestKeycloakProviderGetEmailAddress(t *testing.T) {
	b := testKeycloakBackend("{\"email\": \"michael.bland@gsa.gov\"}")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testKeycloakProvider(bURL.Host, "")

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
}

func TestKeycloakProviderGetEmailAddressAndGroup(t *testing.T) {
	b := testKeycloakBackend("{\"email\": \"michael.bland@gsa.gov\", \"groups\": [\"test-grp1\", \"test-grp2\"]}")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testKeycloakProvider(bURL.Host, "test-grp1")

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
}

// Note that trying to trigger the "failed building request" case is not
// practical, since the only way it can fail is if the URL fails to parse.
func TestKeycloakProviderGetEmailAddressFailedRequest(t *testing.T) {
	b := testKeycloakBackend("unused payload")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testKeycloakProvider(bURL.Host, "")

	// We'll trigger a request failure by using an unexpected access
	// token. Alternatively, we could allow the parsing of the payload as
	// JSON to fail.
	session := &sessions.SessionState{AccessToken: "unexpected_access_token"}
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}

func TestKeycloakProviderGetEmailAddressEmailNotPresentInPayload(t *testing.T) {
	b := testKeycloakBackend("{\"foo\": \"bar\"}")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testKeycloakProvider(bURL.Host, "")

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}
