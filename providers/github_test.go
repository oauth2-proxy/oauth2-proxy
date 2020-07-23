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

func testGitHubBackend(payloads map[string][]string) *httptest.Server {
	pathToQueryMap := map[string][]string{
		"/repo/oauth2-proxy/oauth2-proxy":                       {""},
		"/repos/oauth2-proxy/oauth2-proxy/collaborators/mbland": {""},
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

func TestNewGitHubProvider(t *testing.T) {
	g := NewWithT(t)

	// Test that defaults are set when calling for a new provider with nothing set
	providerData := NewGitHubProvider(&ProviderData{}).Data()
	g.Expect(providerData.ProviderName).To(Equal("GitHub"))
	g.Expect(providerData.LoginURL.String()).To(Equal("https://github.com/login/oauth/authorize"))
	g.Expect(providerData.RedeemURL.String()).To(Equal("https://github.com/login/oauth/access_token"))
	g.Expect(providerData.ProfileURL.String()).To(Equal(""))
	g.Expect(providerData.ValidateURL.String()).To(Equal("https://api.github.com/"))
	g.Expect(providerData.Scope).To(Equal("user:email"))
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
	b := testGitHubBackend(map[string][]string{
		"/user/emails": {`[ {"email": "michael.bland@gsa.gov", "verified": true, "primary": true} ]`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitHubProvider(bURL.Host)

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
}

func TestGitHubProviderGetEmailAddressNotVerified(t *testing.T) {
	b := testGitHubBackend(map[string][]string{
		"/user/emails": {`[ {"email": "michael.bland@gsa.gov", "verified": true, "primary": true} ]`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitHubProvider(bURL.Host)

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Empty(t, "", email)
}

func TestGitHubProviderGetEmailAddressWithOrg(t *testing.T) {
	b := testGitHubBackend(map[string][]string{
		"/user/emails": {`[ {"email": "michael.bland@gsa.gov", "verified": true, "primary": true} ]`},
		"/user/orgs": {
			`[ {"login":"testorg"} ]`,
			`[ {"login":"testorg1"} ]`,
			`[ ]`,
		},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitHubProvider(bURL.Host)
	p.Org = "testorg1"

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
}

func TestGitHubProviderGetEmailAddressWithWriteAccessToPublicRepo(t *testing.T) {
	b := testGitHubBackend(map[string][]string{
		"/repo/oauth2-proxy/oauth2-proxy": {`{"permissions": {"pull": true, "push": true}, "private": false}`},
		"/user/emails":                    {`[ {"email": "michael.bland@gsa.gov", "verified": true, "primary": true} ]`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitHubProvider(bURL.Host)
	p.SetRepo("oauth2-proxy/oauth2-proxy", "")

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
}

func TestGitHubProviderGetEmailAddressWithReadOnlyAccessToPrivateRepo(t *testing.T) {
	b := testGitHubBackend(map[string][]string{
		"/repo/oauth2-proxy/oauth2-proxy": {`{"permissions": {"pull": true, "push": false}, "private": true}`},
		"/user/emails":                    {`[ {"email": "michael.bland@gsa.gov", "verified": true, "primary": true} ]`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitHubProvider(bURL.Host)
	p.SetRepo("oauth2-proxy/oauth2-proxy", "")

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
}

func TestGitHubProviderGetEmailAddressWithWriteAccessToPrivateRepo(t *testing.T) {
	b := testGitHubBackend(map[string][]string{
		"/repo/oauth2-proxy/oauth2-proxy": {`{"permissions": {"pull": true, "push": true}, "private": true}`},
		"/user/emails":                    {`[ {"email": "michael.bland@gsa.gov", "verified": true, "primary": true} ]`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitHubProvider(bURL.Host)
	p.SetRepo("oauth2-proxy/oauth2-proxy", "")

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
}

func TestGitHubProviderGetEmailAddressWithNoAccessToPrivateRepo(t *testing.T) {
	b := testGitHubBackend(map[string][]string{
		"/repo/oauth2-proxy/oauth2-proxy": {},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitHubProvider(bURL.Host)
	p.SetRepo("oauth2-proxy/oauth2-proxy", "")

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}

func TestGitHubProviderGetEmailAddressWithToken(t *testing.T) {
	b := testGitHubBackend(map[string][]string{
		"/user/emails": {`[ {"email": "michael.bland@gsa.gov", "verified": true, "primary": true} ]`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitHubProvider(bURL.Host)
	p.SetRepo("oauth2-proxy/oauth2-proxy", "token")

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
}

// Note that trying to trigger the "failed building request" case is not
// practical, since the only way it can fail is if the URL fails to parse.
func TestGitHubProviderGetEmailAddressFailedRequest(t *testing.T) {
	b := testGitHubBackend(map[string][]string{})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitHubProvider(bURL.Host)

	// We'll trigger a request failure by using an unexpected access
	// token. Alternatively, we could allow the parsing of the payload as
	// JSON to fail.
	session := &sessions.SessionState{AccessToken: "unexpected_access_token"}
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}

func TestGitHubProviderGetEmailAddressEmailNotPresentInPayload(t *testing.T) {
	b := testGitHubBackend(map[string][]string{
		"/user/emails": {`{"foo": "bar"}`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitHubProvider(bURL.Host)

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}

func TestGitHubProviderGetUserName(t *testing.T) {
	b := testGitHubBackend(map[string][]string{
		"/user": {`{"email": "michael.bland@gsa.gov", "login": "mbland"}`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitHubProvider(bURL.Host)

	session := CreateAuthorizedSession()
	email, err := p.GetUserName(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "mbland", email)
}

func TestGitHubProviderGetUserNameWithRepoAndToken(t *testing.T) {
	b := testGitHubBackend(map[string][]string{
		"/user": {`{"email": "michael.bland@gsa.gov", "login": "mbland"}`},
		"/repos/oauth2-proxy/oauth2-proxy/collaborators/mbland": {""},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitHubProvider(bURL.Host)
	p.SetRepo("oauth2-proxy/oauth2-proxy", "token")

	session := CreateAuthorizedSession()
	email, err := p.GetUserName(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "mbland", email)
}

func TestGitHubProviderGetUserNameWithRepoAndTokenWithoutPushAccess(t *testing.T) {
	b := testGitHubBackend(map[string][]string{})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitHubProvider(bURL.Host)
	p.SetRepo("oauth2-proxy/oauth2-proxy", "token")

	session := CreateAuthorizedSession()
	email, err := p.GetUserName(context.Background(), session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}

func TestGitHubProviderGetEmailAddressWithUsername(t *testing.T) {
	b := testGitHubBackend(map[string][]string{
		"/user":        {`{"email": "michael.bland@gsa.gov", "login": "mbland"}`},
		"/user/emails": {`[ {"email": "michael.bland@gsa.gov", "verified": true, "primary": true} ]`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitHubProvider(bURL.Host)
	p.SetUsers([]string{"mbland", "octocat"})

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
}

func TestGitHubProviderGetEmailAddressWithNotAllowedUsername(t *testing.T) {
	b := testGitHubBackend(map[string][]string{
		"/user":        {`{"email": "michael.bland@gsa.gov", "login": "mbland"}`},
		"/user/emails": {`[ {"email": "michael.bland@gsa.gov", "verified": true, "primary": true} ]`},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitHubProvider(bURL.Host)
	p.SetUsers([]string{"octocat"})

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}

func TestGitHubProviderGetEmailAddressWithUsernameAndNotBelongToOrg(t *testing.T) {
	b := testGitHubBackend(map[string][]string{
		"/user":        {`{"email": "michael.bland@gsa.gov", "login": "mbland"}`},
		"/user/emails": {`[ {"email": "michael.bland@gsa.gov", "verified": true, "primary": true} ]`},
		"/user/orgs": {
			`[ {"login":"testorg"} ]`,
			`[ ]`,
		},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitHubProvider(bURL.Host)
	p.SetOrgTeam("not_belong_to", "")
	p.SetUsers([]string{"mbland"})

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
}

func TestGitHubProviderGetEmailAddressWithUsernameAndNoAccessToPrivateRepo(t *testing.T) {
	b := testGitHubBackend(map[string][]string{
		"/user":                           {`{"email": "michael.bland@gsa.gov", "login": "mbland"}`},
		"/user/emails":                    {`[ {"email": "michael.bland@gsa.gov", "verified": true, "primary": true} ]`},
		"/repo/oauth2-proxy/oauth2-proxy": {},
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitHubProvider(bURL.Host)
	p.SetRepo("oauth2-proxy/oauth2-proxy", "")
	p.SetUsers([]string{"mbland"})

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
}
