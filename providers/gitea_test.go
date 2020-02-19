package providers

import (
	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func testGiteaProvider(hostname string) *GiteaProvider {
	p := NewGiteaProvider(
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

func testGiteaBackend(payload []string) *httptest.Server {
	pathToQueryMap := map[string][]string{
		"/api/v1/user": {""},
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

func TestGiteaProviderDefaults(t *testing.T) {
	p := testGiteaProvider("")
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Gitea", p.Data().ProviderName)
	assert.Equal(t, "https://gitea.com/login/oauth/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://gitea.com/login/oauth/access_token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://api.gitea.com/",
		p.Data().ValidateURL.String())
	assert.Equal(t, "user:email", p.Data().Scope)
}

func TestGiteaProviderOverrides(t *testing.T) {
	p := NewGiteaProvider(
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
	assert.Equal(t, "Gitea", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/login/oauth/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/login/oauth/access_token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://api.example.com/",
		p.Data().ValidateURL.String())
	assert.Equal(t, "profile", p.Data().Scope)
}

func TestGiteaProviderGetEmailAddress(t *testing.T) {
	b := testGiteaBackend([]string{`{"email": "michael.bland@gsa.gov", "username": "mbland"}`})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGiteaProvider(bURL.Host)

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
}

// Note that trying to trigger the "failed building request" case is not
// practical, since the only way it can fail is if the URL fails to parse.
func TestGiteaProviderGetEmailAddressFailedRequest(t *testing.T) {
	b := testGiteaBackend([]string{"unused payload"})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGiteaProvider(bURL.Host)

	// We'll trigger a request failure by using an unexpected access
	// token. Alternatively, we could allow the parsing of the payload as
	// JSON to fail.
	session := &sessions.SessionState{AccessToken: "unexpected_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}
