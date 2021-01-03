package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

const grafanaUserPath = "/api/profile"

func testGrafanaProvider(hostname string) *GrafanaProvider {
	p := NewGrafanaProvider(&ProviderData{
		ProviderName: "",
		LoginURL:     &url.URL{},
		RedeemURL:    &url.URL{},
		ProfileURL:   &url.URL{},
		ValidateURL:  &url.URL{},
		Scope:        "",
	})
	if hostname != "" {
		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		updateURL(p.Data().ProfileURL, hostname)
		updateURL(p.Data().ValidateURL, hostname)
	}
	return p
}

func TestGrafanaProviderDefaults(t *testing.T) {
	p := testGrafanaProvider("")
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Grafana", p.Data().ProviderName)
	assert.Equal(t, "https://grafana.com/oauth2/authorize", p.Data().LoginURL.String())
	assert.Equal(t, "https://grafana.com/api/oauth2/token", p.Data().RedeemURL.String())
	assert.Equal(t, "https://grafana.com/api/profile", p.Data().ValidateURL.String())
}

func testGrafanaBackend(payload, path, query string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != path || r.URL.RawQuery != query {
				w.WriteHeader(404)
			} else if !IsAuthorizedInHeader(r.Header) {
				w.WriteHeader(403)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			}
		},
	))
}

func TestGrafanaProviderOverrides(t *testing.T) {
	p := NewGrafanaProvider(
		&ProviderData{
			LoginURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/index.php/apps/oauth2/authorize"},
			RedeemURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/index.php/apps/oauth2/api/v1/token"},
			ValidateURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/test/ocs/v2.php/cloud/user",
			},
			Scope: "profile"})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Grafana", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/index.php/apps/oauth2/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/index.php/apps/oauth2/api/v1/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://example.com/test/ocs/v2.php/cloud/user",
		p.Data().ValidateURL.String())
}

func TestGrafanaProviderGetEmailAddress(t *testing.T) {
	b := testGrafanaBackend(
		`{"id": "1245", "email": "foo@bar.com", "emailConfirmed": 1}`,
		grafanaUserPath,
		"")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGrafanaProvider(bURL.Host)
	p.ValidateURL.Path = grafanaUserPath

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "foo@bar.com", session.Email)
}

// Note that trying to trigger the "failed building request" case is not
// practical, since the only way it can fail is if the URL fails to parse.
func TestGrafanaProviderGetEmailAddressFailedRequest(t *testing.T) {
	b := testGrafanaBackend(
		"unused payload",
		grafanaUserPath,
		"")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGrafanaProvider(bURL.Host)
	p.ValidateURL.Path = grafanaUserPath

	// We'll trigger a request failure by using an unexpected access
	// token. Alternatively, we could allow the parsing of the payload as
	// JSON to fail.
	session := &sessions.SessionState{AccessToken: "unexpected_access_token"}
	err := p.EnrichSession(context.Background(), session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", session.Email)
}

func TestGrafanaProviderGetEmailAddressEmailNotPresentInPayload(t *testing.T) {
	b := testGrafanaBackend(
		`{"id": "1234", "emailConfirmed": 0}`,
		grafanaUserPath,
		"")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGrafanaProvider(bURL.Host)
	p.ValidateURL.Path = grafanaUserPath

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", session.Email)
}
