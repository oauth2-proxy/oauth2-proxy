package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/stretchr/testify/assert"
)

func testGiteaProvider(hostname string, opts options.GitHubOptions) *GitHubProvider {
	p := NewGitHubProvider(
		&ProviderData{
			ProviderName: "Gitea",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{Path: "/api/v1/user/emails"},
			Scope:        ""},
		opts)
	p.ProviderName = "Gitea"

	if hostname != "" {
		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		updateURL(p.Data().ProfileURL, hostname)
		updateURL(p.Data().ValidateURL, hostname)
	}
	return p
}

func testGiteaBackend(payloads map[string][]string) *httptest.Server {
	pathToQueryMap := map[string][]string{
		"/api/v1/repos/oauth2-proxy/oauth2-proxy":                      {""},
		"/api/v1/repos/oauth2-proxy/oauth2-proxy/collaborators/mbland": {""},
		"/api/v1/user":        {""},
		"/api/v1/user/emails": {""},
		"/api/v1/user/orgs":   {"page=1&per_page=100", "page=2&per_page=100", "page=3&per_page=100"},
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
			payload := []string{}
			if ok && validQuery {
				payload, ok = payloads[r.URL.Path]
			}
			if !ok {
				w.WriteHeader(404)
			} else if !validQuery {
				w.WriteHeader(404)
			} else if payload[index] == "" {
				w.WriteHeader(204)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload[index]))
			}
		}))
}

func TestGiteaProvider_ValidateSessionWithBaseUrl(t *testing.T) {
	b := testGiteaBackend(map[string][]string{})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGiteaProvider(bURL.Host, options.GitHubOptions{})

	session := CreateAuthorizedSession()

	valid := p.ValidateSession(context.Background(), session)
	assert.False(t, valid)
}

func TestGiteaProvider_ValidateSessionWithUserEmails(t *testing.T) {
	b := testGiteaBackend(map[string][]string{
		"/api/v1/user/emails": {`[ {"email": "michael.bland@gsa.gov", "verified": true, "primary": true} ]`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGiteaProvider(bURL.Host, options.GitHubOptions{})

	session := CreateAuthorizedSession()

	valid := p.ValidateSession(context.Background(), session)
	assert.True(t, valid)
}
