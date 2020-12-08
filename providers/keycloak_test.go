package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

func testKeycloakProvider(hostname, group string, roles []string) *KeycloakProvider {
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

	if len(roles) > 0 {
		p.SetRoles(roles)
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
	p := testKeycloakProvider("", "", []string{})
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

func TestKeycloakProviderEmailAddress(t *testing.T) {
	b := testKeycloakBackend("{\"email\": \"michael.bland@gsa.gov\"}")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testKeycloakProvider(bURL.Host, "", []string{})

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", session.Email)
}

func TestKeycloakProviderGroups(t *testing.T) {
	b := testKeycloakBackend("{\"email\": \"michael.bland@gsa.gov\", \"groups\": [\"test-grp1\", \"test-grp2\"]}")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testKeycloakProvider(bURL.Host, "test-grp1", []string{})

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.ElementsMatch(t, []string{"group:test-grp1", "group:test-grp2"}, session.Groups)
}

func TestKeycloakProviderRoles(t *testing.T) {
	b := testKeycloakBackend("{\"email\": \"michael.bland@gsa.gov\"}")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testKeycloakProvider(bURL.Host, "", []string{"test-realmrole1"})

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.Equal(t, nil, err)
	// Using roles extracted from default token in providers/auth_test.go
	assert.ElementsMatch(t, []string{"role:test-realmrole1", "role:test-realmrole2", "role:client:test-clientrole1", "role:client:test-clientrole2"}, session.Groups)
}

func TestKeycloakProviderEmailAddressAndGroup(t *testing.T) {
	b := testKeycloakBackend("{\"email\": \"michael.bland@gsa.gov\", \"groups\": [\"test-grp1\", \"test-grp2\"]}")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testKeycloakProvider(bURL.Host, "test-grp1", []string{})

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", session.Email)
	assert.ElementsMatch(t, []string{"group:test-grp1", "group:test-grp2"}, session.Groups)
}

func TestKeycloakProviderEmailAddressAndRoles(t *testing.T) {
	b := testKeycloakBackend("{\"email\": \"michael.bland@gsa.gov\"}")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testKeycloakProvider(bURL.Host, "", []string{"test-realmrole1"})

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", session.Email)
	// Using roles extracted from default token in providers/auth_test.go
	assert.ElementsMatch(t, []string{"role:test-realmrole1", "role:test-realmrole2", "role:client:test-clientrole1", "role:client:test-clientrole2"}, session.Groups)
}

func TestKeycloakProviderEmailAddressAndGroupsAndRoles(t *testing.T) {
	b := testKeycloakBackend("{\"email\": \"michael.bland@gsa.gov\", \"groups\": [\"test-grp1\", \"test-grp2\"]}")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testKeycloakProvider(bURL.Host, "test-grp1", []string{"client:test-clientrole1"})

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", session.Email)
	// Using roles extracted from default token in providers/auth_test.go
	assert.ElementsMatch(t, []string{"group:test-grp1", "group:test-grp2", "role:test-realmrole1", "role:test-realmrole2", "role:client:test-clientrole1", "role:client:test-clientrole2"}, session.Groups)
}

// Note that trying to trigger the "failed building request" case is not
// practical, since the only way it can fail is if the URL fails to parse.
func TestKeycloakProviderFailedRequest(t *testing.T) {
	b := testKeycloakBackend("unused payload")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testKeycloakProvider(bURL.Host, "", []string{})

	// We'll trigger a request failure by using an unexpected access
	// token. Alternatively, we could allow the parsing of the payload as
	// JSON to fail.
	session := &sessions.SessionState{AccessToken: "unexpected_access_token"}
	err := p.EnrichSession(context.Background(), session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", session.Email)
}

func TestKeycloakProviderEmailNotPresentInPayload(t *testing.T) {
	b := testKeycloakBackend("{\"foo\": \"bar\"}")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testKeycloakProvider(bURL.Host, "", []string{})

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", session.Email)
}

func TestKeycloakProviderPrefixAllowedGroups(t *testing.T) {
	b := testKeycloakBackend("{\"email\": \"michael.bland@gsa.gov\", \"groups\": [\"test-grp1\", \"test-grp2\"]}")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testKeycloakProvider(bURL.Host, "test-grp1", []string{"test-realmrole1", "client:test-clientrole1"})

	allowedGroups := p.PrefixAllowedGroups()
	assert.ElementsMatch(t, []string{"group:test-grp1", "role:test-realmrole1", "role:client:test-clientrole1"}, allowedGroups)
}

func TestKeycloakProviderPrefixAllowedGroupsNoGroup(t *testing.T) {
	b := testKeycloakBackend("{\"email\": \"michael.bland@gsa.gov\", \"groups\": [\"test-grp1\", \"test-grp2\"]}")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testKeycloakProvider(bURL.Host, "", []string{"test-realmrole1", "client:test-clientrole1"})

	allowedGroups := p.PrefixAllowedGroups()
	assert.ElementsMatch(t, []string{"role:test-realmrole1", "role:client:test-clientrole1"}, allowedGroups)
}

func TestKeycloakProviderPrefixAllowedGroupsNoRoles(t *testing.T) {
	b := testKeycloakBackend("{\"email\": \"michael.bland@gsa.gov\", \"groups\": [\"test-grp1\", \"test-grp2\"]}")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testKeycloakProvider(bURL.Host, "test-grp1", []string{})

	allowedGroups := p.PrefixAllowedGroups()
	assert.ElementsMatch(t, []string{"group:test-grp1"}, allowedGroups)
}

func TestKeycloakProviderPrefixAllowedGroupsEmpty(t *testing.T) {
	b := testKeycloakBackend("{\"email\": \"michael.bland@gsa.gov\", \"groups\": [\"test-grp1\", \"test-grp2\"]}")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testKeycloakProvider(bURL.Host, "", []string{})

	allowedGroups := p.PrefixAllowedGroups()
	assert.Empty(t, allowedGroups)
}
