package providers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/stretchr/testify/assert"
)

func testGitHubProvider(hostname string) *GitHubProvider {
	p := NewGitHubProvider(
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

func testGitHubBackend(payload []string) *httptest.Server {
	pathToQueryMap := map[string][]string{
		"/user":        {""},
		"/user/emails": {""},
		"/user/orgs":   {"page=1&per_page=100", "page=2&per_page=100", "page=3&per_page=100"},
	}

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			query, ok := pathToQueryMap[r.URL.Path]
			validQuery := false
			index := 0
			for i, q := range query {
				if q == r.URL.RawQuery {
					validQuery = true
					index = i
				}
			}
			if !ok {
				w.WriteHeader(404)
			} else if !validQuery {
				w.WriteHeader(404)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload[index]))
			}
		}))
}

func TestGitHubProviderDefaults(t *testing.T) {
	p := testGitHubProvider("")
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "GitHub", p.Data().ProviderName)
	assert.Equal(t, "https://github.com/login/oauth/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://github.com/login/oauth/access_token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://api.github.com/",
		p.Data().ValidateURL.String())
	assert.Equal(t, "user:email", p.Data().Scope)
}

func TestGitHubProviderOverrides(t *testing.T) {
	p := NewGitHubProvider(
		&ProviderData{
			LoginURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/login/oauth/authorize"},
			RedeemURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/login/oauth/access_token"},
			ValidateURL: &url.URL{
				Scheme: "https",
				Host:   "api.example.com",
				Path:   "/"},
			Scope: "profile"})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "GitHub", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/login/oauth/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/login/oauth/access_token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://api.example.com/",
		p.Data().ValidateURL.String())
	assert.Equal(t, "profile", p.Data().Scope)
}

func TestGitHubProviderGetEmailAddress(t *testing.T) {
	b := testGitHubBackend([]string{`[ {"email": "michael.bland@gsa.gov", "verified": true, "primary": true} ]`})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitHubProvider(bURL.Host)

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
}

func TestGitHubProviderGetEmailAddressNotVerified(t *testing.T) {
	b := testGitHubBackend([]string{`[ {"email": "michael.bland@gsa.gov", "verified": false, "primary": true} ]`})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitHubProvider(bURL.Host)

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.Empty(t, "", email)
}

func TestGitHubProviderGetEmailAddressWithOrg(t *testing.T) {
	b := testGitHubBackend([]string{
		`[ {"email": "michael.bland@gsa.gov", "primary": true, "verified": true, "login":"testorg"} ]`,
		`[ {"email": "michael.bland1@gsa.gov", "primary": true, "verified": true, "login":"testorg1"} ]`,
		`[ ]`,
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitHubProvider(bURL.Host)
	p.Org = "testorg1"

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
}

// Note that trying to trigger the "failed building request" case is not
// practical, since the only way it can fail is if the URL fails to parse.
func TestGitHubProviderGetEmailAddressFailedRequest(t *testing.T) {
	b := testGitHubBackend([]string{"unused payload"})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitHubProvider(bURL.Host)

	// We'll trigger a request failure by using an unexpected access
	// token. Alternatively, we could allow the parsing of the payload as
	// JSON to fail.
	session := &sessions.SessionState{AccessToken: "unexpected_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}

func TestGitHubProviderGetEmailAddressEmailNotPresentInPayload(t *testing.T) {
	b := testGitHubBackend([]string{"{\"foo\": \"bar\"}"})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitHubProvider(bURL.Host)

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}

func TestGitHubProviderGetUserName(t *testing.T) {
	b := testGitHubBackend([]string{`{"email": "michael.bland@gsa.gov", "login": "mbland"}`})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitHubProvider(bURL.Host)

	session := CreateAuthorizedSession()
	email, err := p.GetUserName(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "mbland", email)
}
