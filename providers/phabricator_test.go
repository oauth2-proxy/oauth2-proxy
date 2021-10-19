package providers

import (
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

func testPhabricatorProvider(hostname string) *PhabricatorProvider {
	p := NewPhabricatorProvider(
		&ProviderData{
			LoginURL: &url.URL{Host: hostname, Scheme: "http", Path: "/oauthserver/auth/"},
		})
	return p
}

func testPhabricatorBackend(whoamiPayload, projectsearchPayload string) *httptest.Server {
	paths := map[string]string{
		"/api/user.whoami":    whoamiPayload,
		"/api/project.search": projectsearchPayload,
	}

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			url := r.URL
			log.Printf("%s %s\n", url.Path, url.RawQuery)
			if paths[url.Path] == "" {
				log.Printf("%s not in %+v\n", url.Path, paths)
				w.WriteHeader(404)
			} else if !IsAuthorizedInURL(r.URL) && r.URL.Path != "/api/project.search" {
				w.WriteHeader(403)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(paths[url.Path]))
			}
		}))
}

func TestNewPhabricatorProvider(t *testing.T) {
	g := NewWithT(t)

	// Test that defaults are set when calling for a new provider with only LoginURL set
	providerData := NewPhabricatorProvider(
		&ProviderData{LoginURL: &url.URL{Host: "localhost", Scheme: "http", Path: "/oauthserver/auth/"}},
	).Data()

	g.Expect(providerData.ProviderName).To(Equal("Phabricator"))
	g.Expect(providerData.LoginURL.String()).To(Equal("http://localhost/oauthserver/auth/"))
	g.Expect(providerData.RedeemURL.String()).To(Equal("http://localhost/oauthserver/token/"))
	g.Expect(providerData.ProfileURL.String()).To(Equal("http://localhost/api/user.whoami"))
	g.Expect(providerData.ValidateURL.String()).To(Equal("http://localhost/api/user.whoami"))
	g.Expect(providerData.Scope).To(Equal(""))
}

func TestPhabricatorProviderOverrides(t *testing.T) {
	p := NewPhabricatorProvider(
		&ProviderData{
			LoginURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauthserver/auth/"},
			RedeemURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauthserver/token/"},
			ValidateURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/api/user.whoami"},
		})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Phabricator", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/oauthserver/auth/",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/oauthserver/token/",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://example.com/api/user.whoami",
		p.Data().ValidateURL.String())
}

func TestPhabricatorProviderEnrichSession(t *testing.T) {
	b := testPhabricatorBackend(
		`{"result": {"primaryEmail": "user@example.com", "userName": "user"}}`,
		`{"result": {"data": [{"fields": {"slug": "general_access"}}]}}`,
	)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testPhabricatorProvider(bURL.Host)

	session := CreateAuthorizedSession()
	err := p.EnrichSession(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "user@example.com", session.Email)
	assert.Equal(t, "user", session.User)
	assert.Equal(t, []string{"general_access"}, session.Groups)
}

func TestPhabricatorProviderEnrichSessionFailedRequest(t *testing.T) {
	b := testPhabricatorBackend(
		`{"result": {"primaryEmail": "user@example.com", "userName": "user"}}`,
		`{"result": {"data": [{"fields": {"slug": "general_access"}}]}}`,
	)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testPhabricatorProvider(bURL.Host)

	session := &sessions.SessionState{AccessToken: "unexpected_access_token"}
	err := p.EnrichSession(context.Background(), session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", session.Email)
	assert.Equal(t, "", session.User)
	assert.Empty(t, session.Groups)
}

func TestPhabricatorProviderFilterGroups(t *testing.T) {
	b := testPhabricatorBackend(
		`{"result": {"primaryEmail": "user@example.com", "userName": "user"}}`,
		`{"result": {"data": [
			{"fields": {"slug": "should_be_ignored"}},
			{"fields": {"slug": "something_team"}},
			{"fields": {"slug": "an_ignored_team_project"}},
			{"fields": {"slug": "general_access"}}
		]}}`,
	)
	defer b.Close()

	tests := []struct {
		regex          string
		expectedGroups []string
	}{
		{
			regex:          ``,
			expectedGroups: []string{"should_be_ignored", "something_team", "an_ignored_team_project", "general_access"},
		},
		{
			regex:          `.*`,
			expectedGroups: []string{"should_be_ignored", "something_team", "an_ignored_team_project", "general_access"},
		},
		{
			regex:          `.+_access$`,
			expectedGroups: []string{"general_access"},
		},
		{
			regex:          `.+_(access|team)$`,
			expectedGroups: []string{"something_team", "general_access"},
		},
	}

	for _, test := range tests {
		t.Run(test.regex, func(t *testing.T) {
			bURL, _ := url.Parse(b.URL)
			p := testPhabricatorProvider(bURL.Host)
			err := p.AddGroupFilter(test.regex)
			assert.Equal(t, nil, err)

			session := CreateAuthorizedSession()
			err = p.EnrichSession(context.Background(), session)
			assert.Equal(t, nil, err)
			assert.Equal(t, "user@example.com", session.Email)
			assert.Equal(t, "user", session.User)
			assert.Equal(t, test.expectedGroups, session.Groups)
		})
	}
}
