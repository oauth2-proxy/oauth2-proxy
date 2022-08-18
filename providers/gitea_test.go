package providers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

func testGiteaProvider(hostname string, opts options.GiteaOptions) *GiteaProvider {
	p := NewGiteaProvider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""},
		opts)
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
		"/api/v1/user":                         {""},
		"/api/v1/user/emails":                  {""},
		"/api/v1/orgs/testorg1/members/mbland": {""},
		// "/api/v1/user/orgs":   {"page=1&per_page=100", "page=2&per_page=100", "page=3&per_page=100"},
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

func TestNewGiteaProvider(t *testing.T) {
	g := NewWithT(t)

	// Test that defaults are set when calling for a new provider with nothing set
	providerData := NewGiteaProvider(&ProviderData{}, options.GiteaOptions{}).Data()
	g.Expect(providerData.ProviderName).To(Equal("Gitea"))
	g.Expect(providerData.LoginURL.String()).To(Equal("https://try.gitea.io/login/oauth/authorize"))
	g.Expect(providerData.RedeemURL.String()).To(Equal("https://try.gitea.io/login/oauth/access_token"))
	g.Expect(providerData.ProfileURL.String()).To(Equal(""))
	g.Expect(providerData.ValidateURL.String()).To(Equal("https://try.gitea.io/api/v1/user"))
	g.Expect(providerData.Scope).To(Equal(""))
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
				Host:   "example.com",
				Path:   "/api/v1"},
			Scope: "profile"},
		options.GiteaOptions{})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Gitea", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/login/oauth/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/login/oauth/access_token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://example.com/api/v1",
		p.Data().ValidateURL.String())
	assert.Equal(t, "profile", p.Data().Scope)
}

func TestGiteaProvider_EnrichSession(t *testing.T) {
	b := testGiteaBackend(map[string][]string{
		"/api/v1/user/emails": {`[ {"email": "michael.bland@gsa.gov", "verified": true, "primary": true} ]`},
		"/api/v1/user":        {`{"id": 1337, "login": "mbland", "email": "michael.bland@gsa.gov"}`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGiteaProvider(bURL.Host, options.GiteaOptions{})

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.NoError(t, err)
	assert.Equal(t, "michael.bland@gsa.gov", session.Email)
	assert.Equal(t, "mbland", session.User)
}

func TestGiteaProvider_EnrichSessionEmailNotVerified(t *testing.T) {
	b := testGiteaBackend(map[string][]string{
		"/api/v1/user/emails": {`[ {"email": "michael.bland@gsa.gov", "verified": false, "primary": true} ]`},
		"/api/v1/user":        {`{"id": 1337, "login": "mbland", "email": "michael.bland@gsa.gov"}`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGiteaProvider(bURL.Host, options.GiteaOptions{})

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.NoError(t, err)
	assert.Empty(t, session.Email)
}

func TestGiteaProvider_EnrichSessionWithOrg(t *testing.T) {
	b := testGiteaBackend(map[string][]string{
		"/api/v1/user/emails":                  {`[ {"email": "michael.bland@gsa.gov", "verified": true, "primary": true} ]`},
		"/api/v1/user":                         {`{"id": 1337, "login": "mbland", "email": "michael.bland@gsa.gov"}`},
		"/api/v1/orgs/testorg1/members/mbland": {""},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGiteaProvider(bURL.Host,
		options.GiteaOptions{
			Org: "testorg1",
		},
	)

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.NoError(t, err)
	assert.Equal(t, "michael.bland@gsa.gov", session.Email)
	assert.Equal(t, "mbland", session.User)
}

func TestGiteaProvider_EnrichSessionWithReadAccessToPublicRepo(t *testing.T) {
	b := testGiteaBackend(map[string][]string{
		"/api/v1/user/emails":                     {`[ {"email": "michael.bland@gsa.gov", "verified": true, "primary": true} ]`},
		"/api/v1/user":                            {`{"id": 1337, "login": "mbland", "email": "michael.bland@gsa.gov"}`},
		"/api/v1/repos/oauth2-proxy/oauth2-proxy": {`{"permissions": {"pull": true, "push": false}, "private": false}`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGiteaProvider(bURL.Host,
		options.GiteaOptions{
			Repo: "oauth2-proxy/oauth2-proxy",
		},
	)

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.NoError(t, err, errors.New("user is not in repo"))
	assert.Empty(t, session.Email)
	assert.Equal(t, "mbland", session.User)
}

func TestGiteaProvider_EnrichSessionWithWriteAccessToPublicRepo(t *testing.T) {
	b := testGiteaBackend(map[string][]string{
		"/api/v1/user/emails":                     {`[ {"email": "michael.bland@gsa.gov", "verified": true, "primary": true} ]`},
		"/api/v1/user":                            {`{"id": 1337, "login": "mbland", "email": "michael.bland@gsa.gov"}`},
		"/api/v1/repos/oauth2-proxy/oauth2-proxy": {`{"permissions": {"pull": true, "push": true}, "private": false}`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGiteaProvider(bURL.Host,
		options.GiteaOptions{
			Repo: "oauth2-proxy/oauth2-proxy",
		},
	)

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.NoError(t, err)
	assert.Equal(t, "michael.bland@gsa.gov", session.Email)
	assert.Equal(t, "mbland", session.User)
}

func TestGiteaProvider_EnrichSessionWithReadOnlyAccessToPrivateRepo(t *testing.T) {
	b := testGiteaBackend(map[string][]string{
		"/api/v1/user/emails":                     {`[ {"email": "michael.bland@gsa.gov", "verified": true, "primary": true} ]`},
		"/api/v1/user":                            {`{"id": 1337, "login": "mbland", "email": "michael.bland@gsa.gov"}`},
		"/api/v1/repos/oauth2-proxy/oauth2-proxy": {`{"permissions": {"pull": true, "push": false}, "private": true}`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGiteaProvider(bURL.Host,
		options.GiteaOptions{
			Repo: "oauth2-proxy/oauth2-proxy",
		},
	)

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.NoError(t, err)
	assert.Equal(t, "michael.bland@gsa.gov", session.Email)
	assert.Equal(t, "mbland", session.User)
}

func TestGiteaProvider_EnrichSessionWithWriteAccessToPrivateRepo(t *testing.T) {
	b := testGiteaBackend(map[string][]string{
		"/api/v1/user/emails":                     {`[ {"email": "michael.bland@gsa.gov", "verified": true, "primary": true} ]`},
		"/api/v1/user":                            {`{"id": 1337, "login": "mbland", "email": "michael.bland@gsa.gov"}`},
		"/api/v1/repos/oauth2-proxy/oauth2-proxy": {`{"permissions": {"pull": true, "push": true}, "private": true}`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGiteaProvider(bURL.Host,
		options.GiteaOptions{
			Repo: "oauth2-proxy/oauth2-proxy",
		},
	)

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.NoError(t, err)
	assert.Equal(t, "michael.bland@gsa.gov", session.Email)
	assert.Equal(t, "mbland", session.User)
}

func TestGiteaProvider_EnrichSessionWithNoAccessToPrivateRepo(t *testing.T) {
	b := testGiteaBackend(map[string][]string{
		"/api/v1/user/emails":                     {`[ {"email": "michael.bland@gsa.gov", "verified": true, "primary": true} ]`},
		"/api/v1/user":                            {`{"id": 1337, "login": "mbland", "email": "michael.bland@gsa.gov"}`},
		"/api/v1/repos/oauth2-proxy/oauth2-proxy": {`{}`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGiteaProvider(bURL.Host,
		options.GiteaOptions{
			Repo: "oauth2-proxy/oauth2-proxy",
		},
	)

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.NoError(t, err)
	assert.Empty(t, session.Email)
	assert.Equal(t, "mbland", session.User)
}

// Note that trying to trigger the "failed building request" case is not
// practical, since the only way it can fail is if the URL fails to parse.
func TestGiteaProvider_EnrichSessionFailedRequest(t *testing.T) {
	b := testGiteaBackend(map[string][]string{})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGiteaProvider(bURL.Host, options.GiteaOptions{})

	// We'll trigger a request failure by using an unexpected access
	// token. Alternatively, we could allow the parsing of the payload as
	// JSON to fail.
	session := &sessions.SessionState{AccessToken: "unexpected_access_token"}
	err := p.EnrichSession(context.Background(), session)
	assert.Error(t, err)
	assert.Empty(t, session.Email)
	assert.Empty(t, session.User)
}

func TestGiteaProvider_EnrichSessionNotPresentInPayload(t *testing.T) {
	b := testGiteaBackend(map[string][]string{
		"/api/v1/user/emails": {`{"foo": "bar"}`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGiteaProvider(bURL.Host, options.GiteaOptions{})

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.Error(t, err)
	assert.Empty(t, session.Email)
}

func TestGiteaProvider_getUser(t *testing.T) {
	b := testGiteaBackend(map[string][]string{
		"/api/v1/user": {`{"email": "michael.bland@gsa.gov", "login": "mbland"}`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGiteaProvider(bURL.Host, options.GiteaOptions{})

	session := CreateAuthorizedSession()
	err := p.getUser(context.Background(), session)
	assert.NoError(t, err)
	assert.Equal(t, "mbland", session.User)
}

func TestGiteaProvider_EnrichSessionWithUsername(t *testing.T) {
	b := testGiteaBackend(map[string][]string{
		"/api/v1/user":        {`{"email": "michael.bland@gsa.gov", "login": "mbland"}`},
		"/api/v1/user/emails": {`[ {"email": "michael.bland@gsa.gov", "verified": true, "primary": true} ]`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGiteaProvider(bURL.Host,
		options.GiteaOptions{
			Users: []string{"mbland", "octocat"},
		},
	)

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.NoError(t, err)
	assert.Equal(t, "michael.bland@gsa.gov", session.Email)
	assert.Equal(t, "mbland", session.User)
}

func TestGiteaProvider_EnrichSessionWithNotAllowedUsername(t *testing.T) {
	b := testGiteaBackend(map[string][]string{
		"/api/v1/user":        {`{"email": "michael.bland@gsa.gov", "login": "mbland"}`},
		"/api/v1/user/emails": {`[ {"email": "michael.bland@gsa.gov", "verified": true, "primary": true} ]`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGiteaProvider(bURL.Host,
		options.GiteaOptions{
			Users: []string{"octocat"},
		},
	)

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.NoError(t, err)
	assert.Empty(t, session.Email)
	assert.Equal(t, "mbland", session.User)
}

func TestGiteaProvider_EnrichSessionWithUsernameAndNotBelongToOrg(t *testing.T) {
	b := testGiteaBackend(map[string][]string{
		"/api/v1/user":        {`{"email": "michael.bland@gsa.gov", "login": "mbland"}`},
		"/api/v1/user/emails": {`[ {"email": "michael.bland@gsa.gov", "verified": true, "primary": true} ]`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGiteaProvider(bURL.Host,
		options.GiteaOptions{
			Org:   "testorg1",
			Users: []string{"mbland"},
		},
	)

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.NoError(t, err)
	assert.Equal(t, "michael.bland@gsa.gov", session.Email)
	assert.Equal(t, "mbland", session.User)
}

func TestGiteaProvider_EnrichSessionWithUsernameAndNoAccessToPrivateRepo(t *testing.T) {
	b := testGiteaBackend(map[string][]string{
		"/api/v1/user":                            {`{"email": "michael.bland@gsa.gov", "login": "mbland"}`},
		"/api/v1/user/emails":                     {`[ {"email": "michael.bland@gsa.gov", "verified": true, "primary": true} ]`},
		"/api/v1/repos/oauth2-proxy/oauth2-proxy": {`{}`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGiteaProvider(bURL.Host,
		options.GiteaOptions{
			Repo:  "oauth2-proxy/oauth2-proxy",
			Users: []string{"mbland"},
		},
	)

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.NoError(t, err)
	assert.Equal(t, "michael.bland@gsa.gov", session.Email)
	assert.Equal(t, "mbland", session.User)
}
