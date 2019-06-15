package providers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/stretchr/testify/assert"
)

func testGitLabProvider(hostname string) *GitLabProvider {
	p := NewGitLabProvider(
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

func testGitLabBackend(payloadUser string, payloadGroups string, payloadUserEmail string) *httptest.Server {
	query := "access_token=imaginary_access_token"
	userPath := "/api/v4/user"
	groupsPath := "/api/v4/groups"
	userEmailsPath := "/api/v4/user/emails"

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.RawQuery != query {
				w.WriteHeader(401)
				return
			}
			switch r.URL.Path {
			case userPath:
				w.WriteHeader(200)
				w.Write([]byte(payloadUser))
			case userEmailsPath:
				w.WriteHeader(200)
				w.Write([]byte(payloadUserEmail))
			case groupsPath:
				w.WriteHeader(200)
				w.Write([]byte(payloadGroups))
			default:
				w.WriteHeader(404)
			}
		}))
}

func TestGitLabProviderDefaults(t *testing.T) {
	p := testGitLabProvider("")
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "GitLab", p.Data().ProviderName)
	assert.Equal(t, "https://gitlab.com/oauth/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://gitlab.com/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://gitlab.com/api/v4",
		p.Data().ValidateURL.String())
	assert.Equal(t, "read_user", p.Data().Scope)
}

func TestGitLabProviderOverrides(t *testing.T) {
	p := NewGitLabProvider(
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
	assert.Equal(t, "GitLab", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/oauth/auth",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://example.com/api/v4/user",
		p.Data().ValidateURL.String())
	assert.Equal(t, "profile read_user", p.Data().Scope)
}

func TestGitLabProviderGetEmailAddress(t *testing.T) {
	b := testGitLabBackend("{\"email\": \"michael.bland@gsa.gov\"}", "", "")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitLabProvider(bURL.Host)

	session := &sessions.SessionState{AccessToken: "imaginary_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
}

// Note that trying to trigger the "failed building request" case is not
// practical, since the only way it can fail is if the URL fails to parse.
func TestGitLabProviderGetEmailAddressFailedRequest(t *testing.T) {
	b := testGitLabBackend("unused payload", "", "")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitLabProvider(bURL.Host)

	// We'll trigger a request failure by using an unexpected access
	// token. Alternatively, we could allow the parsing of the payload as
	// JSON to fail.
	session := &sessions.SessionState{AccessToken: "unexpected_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}

func TestGitLabProviderGetEmailAddressEmailNotPresentInPayload(t *testing.T) {
	b := testGitLabBackend("{\"foo\": \"bar\"}", "", "")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitLabProvider(bURL.Host)

	session := &sessions.SessionState{AccessToken: "imaginary_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}

func TestGitLabProviderGetEmailAddressWithEmailDomain(t *testing.T) {
	b := testGitLabBackend("{\"email\": \"ruben.wagner@example.com\"}", "", "[{\"email\": \"ruben.wagner@example2.com\"}]")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitLabProvider(bURL.Host)
	p.SetEmailDomains([]string{"@example2.com"})

	session := &sessions.SessionState{AccessToken: "imaginary_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "ruben.wagner@example2.com", email)
}
func TestGitLabProviderGetEmailAddressWithGroups(t *testing.T) {
	b := testGitLabBackend("{\"email\": \"ruben.wagner@example.com\"}", "[{\"name\": \"testgroup\"}, {\"name\": \"testgroup2\"}]", "")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitLabProvider(bURL.Host)
	p.SetGroup("testgroup")
	assert.Equal(t, "read_user api", p.Scope)

	session := &sessions.SessionState{AccessToken: "imaginary_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "ruben.wagner@example.com", email)
}

func TestGitLabProviderGetEmailAddressWithGroupsInvalid(t *testing.T) {
	b := testGitLabBackend("{\"email\": \"ruben.wagner@example.com\"}", "[{\"name\": \"testgroup2\"}]", "")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testGitLabProvider(bURL.Host)
	p.SetGroup("testgroup")
	assert.Equal(t, "read_user api", p.Scope)

	session := &sessions.SessionState{AccessToken: "imaginary_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}
