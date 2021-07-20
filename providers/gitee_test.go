package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

func testGiteeProvider(hostname string) *GiteeProvider {
	p := NewGiteeProvider(
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

func testGiteeBackend(payloads map[string][]string) *httptest.Server {
	pathToQueryMap := map[string][]string{
		"/api/v5/repos/oauth2-proxy/oauth2-proxy":                       {""},
		"/api/v5/repos/oauth2-proxy/oauth2-proxy/collaborators/xwzqmxx": {"access_token=token"},
		"/api/v5/user":      {"access_token=imaginary_access_token"},
		"/api/v5/emails":    {"access_token=imaginary_access_token"},
		"/api/v5/user/orgs": {"access_token=imaginary_access_token&page=1&per_page=20", "access_token=imaginary_access_token&page=2&per_page=20"},
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
			payload := make([]string, 0)
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

func TestNewGiteeProvider(t *testing.T) {
	g := gomega.NewWithT(t)

	// Test that defaults are set when calling for a new provider with nothing set
	providerData := NewGiteeProvider(&ProviderData{}).Data()
	g.Expect(providerData.ProviderName).To(gomega.Equal("Gitee"))
	g.Expect(providerData.LoginURL.String()).To(gomega.Equal("https://gitee.com/oauth/authorize"))
	g.Expect(providerData.RedeemURL.String()).To(gomega.Equal("https://gitee.com/oauth/token"))
	g.Expect(providerData.ProfileURL.String()).To(gomega.Equal(""))
	g.Expect(providerData.ValidateURL.String()).To(gomega.Equal("https://gitee.com/api/v5"))
	g.Expect(providerData.Scope).To(gomega.Equal("user_info emails"))
}

func TestGiteeProvider_getEmail(t *testing.T) {
	b := testGiteeBackend(map[string][]string{
		"/api/v5/emails": {`[{"email":"xwzqmxx@org.com","state":"confirmed","scope":["primary","secure","notified"]}]`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGiteeProvider(bURL.Host)

	session := CreateAuthorizedSession()
	err := p.getEmail(context.Background(), session)
	assert.NoError(t, err)
	assert.Equal(t, "xwzqmxx@org.com", session.Email)
}

func TestGiteeProvider_getEmailNotVerified(t *testing.T) {
	b := testGiteeBackend(map[string][]string{
		"/api/v5/emails": {`[{"email":"xwzqmxx@org.com","state":"unconfirmed","scope":["primary","secure","notified"]}]`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGiteeProvider(bURL.Host)

	session := CreateAuthorizedSession()
	err := p.getEmail(context.Background(), session)
	assert.NoError(t, err)
	assert.Empty(t, session.Email)
}

func TestGiteeProvider_getEmailWithOrg(t *testing.T) {
	b := testGiteeBackend(map[string][]string{
		"/api/v5/emails": {`[{"email":"xwzqmxx@org.com","state":"confirmed","scope":["primary","secure","notified"]}]`},
		"/api/v5/user/orgs": {
			`[ {"login":"testorg"} ,{"login":"testorg1"}]`,
		},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGiteeProvider(bURL.Host)
	p.Org = "testorg1"

	session := CreateAuthorizedSession()
	err := p.getEmail(context.Background(), session)
	assert.NoError(t, err)
	assert.Equal(t, "xwzqmxx@org.com", session.Email)
}

func TestGiteeProvider_getEmailFailedRequest(t *testing.T) {
	b := testGiteeBackend(map[string][]string{})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGiteeProvider(bURL.Host)

	// We'll trigger a request failure by using an unexpected access
	// token. Alternatively, we could allow the parsing of the payload as
	// JSON to fail.
	session := &sessions.SessionState{AccessToken: "unexpected_access_token"}
	err := p.getEmail(context.Background(), session)
	assert.Error(t, err)
	assert.Empty(t, session.Email)
}

func TestGiteeProvider_getUser(t *testing.T) {
	b := testGiteeBackend(map[string][]string{
		"/api/v5/user": {`{"id":9573, "email": "xwzqmxx@org.com", "login": "xwzqmxx"}`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGiteeProvider(bURL.Host)

	session := CreateAuthorizedSession()
	err := p.getUser(context.Background(), session)
	assert.NoError(t, err)
	assert.Equal(t, "xwzqmxx", session.User)
}

func TestGiteeProvider_getEmailWithWriteAccessToPrivateRepo(t *testing.T) {
	b := testGiteeBackend(map[string][]string{
		"/api/v5/repos/oauth2-proxy/oauth2-proxy": {`{"permissions": {"pull": true, "push": true}, "private": true}`},
		"/api/v5/emails": {`[{"email":"xwzqmxx@org.com","state":"confirmed","scope":["primary","secure","notified"]}]`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGiteeProvider(bURL.Host)
	p.SetRepo("oauth2-proxy/oauth2-proxy", "")

	session := CreateAuthorizedSession()
	err := p.getEmail(context.Background(), session)
	assert.NoError(t, err)
	assert.Equal(t, "xwzqmxx@org.com", session.Email)
}

func TestGiteeProvider_getUserWithRepoAndToken(t *testing.T) {
	b := testGiteeBackend(map[string][]string{
		"/api/v5/user": {`{"id":9573, "email": "xwzqmxx@org.com", "login": "xwzqmxx"}`},
		"/api/v5/repos/oauth2-proxy/oauth2-proxy/collaborators/xwzqmxx": {""},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGiteeProvider(bURL.Host)
	p.SetRepo("oauth2-proxy/oauth2-proxy", "token")

	session := CreateAuthorizedSession()
	err := p.getUser(context.Background(), session)
	assert.NoError(t, err)
	assert.Equal(t, "xwzqmxx", session.User)
}
