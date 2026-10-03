package providers

import (
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

func testBitbucketProvider(hostname, team string, repository string) *BitbucketProvider {
	p := NewBitbucketProvider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""},
		options.BitbucketOptions{
			Team:       team,
			Workspace:  team,
			Repository: repository,
		},
	)

	if hostname != "" {
		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		updateURL(p.Data().ProfileURL, hostname)
		updateURL(p.Data().ValidateURL, hostname)
	}
	return p
}

func testBitbucketBackend(payload string) *httptest.Server {
	paths := map[string]bool{
		"/2.0/user/emails": true,
	}

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			url := r.URL
			if !paths[url.Path] {
				log.Printf("%s not in %+v\n", url.Path, paths)
				w.WriteHeader(404)
			} else if !IsAuthorizedInHeader(r.Header) {
				w.WriteHeader(403)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			}
		}))
}

func testBitbucketBackendWithWorkspace(emailPayload, workspacePayload string) *httptest.Server {
	return testBitbucketBackendFull(emailPayload, workspacePayload, "")
}

func testBitbucketBackendFull(emailPayload, workspacePayload, repoPayload string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if !IsAuthorizedInHeader(r.Header) {
				w.WriteHeader(403)
				return
			}
			switch {
			case r.URL.Path == "/2.0/user/emails":
				w.WriteHeader(200)
				w.Write([]byte(emailPayload))
			case r.URL.Path == "/2.0/user/workspaces":
				w.WriteHeader(200)
				w.Write([]byte(workspacePayload))
			case strings.HasPrefix(r.URL.Path, "/2.0/repositories/"):
				w.WriteHeader(200)
				w.Write([]byte(repoPayload))
			default:
				log.Printf("%s not handled\n", r.URL.Path)
				w.WriteHeader(404)
			}
		}))
}

func TestNewBitbucketProvider(t *testing.T) {
	g := NewWithT(t)

	// Test that defaults are set when calling for a new provider with nothing set
	providerData := NewBitbucketProvider(&ProviderData{}, options.BitbucketOptions{}).Data()
	g.Expect(providerData.ProviderName).To(Equal("Bitbucket"))
	g.Expect(providerData.LoginURL.String()).To(Equal("https://bitbucket.org/site/oauth2/authorize"))
	g.Expect(providerData.RedeemURL.String()).To(Equal("https://bitbucket.org/site/oauth2/access_token"))
	g.Expect(providerData.ProfileURL.String()).To(Equal(""))
	g.Expect(providerData.ValidateURL.String()).To(Equal("https://api.bitbucket.org/2.0/user/emails"))
	g.Expect(providerData.Scope).To(Equal("email"))
}

func TestBitbucketProviderScopeAdjustForTeam(t *testing.T) {
	p := testBitbucketProvider("", "test-team", "")
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "email account", p.Data().Scope)
}

func TestBitbucketProviderScopeAdjustForRepository(t *testing.T) {
	p := testBitbucketProvider("", "", "rest-repo")
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "email repository", p.Data().Scope)
}

func TestBitbucketProviderOverrides(t *testing.T) {
	p := NewBitbucketProvider(
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
			Scope: "profile"},
		options.BitbucketOptions{})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Bitbucket", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/oauth/auth",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://example.com/api/v3/user",
		p.Data().ValidateURL.String())
	assert.Equal(t, "profile", p.Data().Scope)
}

func TestBitbucketProviderGetEmailAddress(t *testing.T) {
	b := testBitbucketBackend("{\"values\": [ { \"email\": \"michael.bland@gsa.gov\", \"is_primary\": true } ] }")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testBitbucketProvider(bURL.Host, "", "")

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
}

func TestBitbucketProviderGetEmailAddressAndGroup(t *testing.T) {
	emailPayload := `{"values": [ { "email": "michael.bland@gsa.gov", "is_primary": true } ] }`
	workspacePayload := `{"values": [ { "type": "workspace_access", "workspace": { "slug": "bioinformatics" } } ] }`
	b := testBitbucketBackendWithWorkspace(emailPayload, workspacePayload)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testBitbucketProvider(bURL.Host, "bioinformatics", "")

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
}

func TestBitbucketProviderGetEmailAddressMultipleWorkspaces(t *testing.T) {
	emailPayload := `{"values": [ { "email": "michael.bland@gsa.gov", "is_primary": true } ] }`
	// target workspace is the last entry to exercise the full loop
	workspacePayload := `{"values": [
		{ "type": "workspace_access", "workspace": { "slug": "other-team-1" } },
		{ "type": "workspace_access", "workspace": { "slug": "other-team-2" } },
		{ "type": "workspace_access", "workspace": { "slug": "bioinformatics" } }
	]}`
	b := testBitbucketBackendWithWorkspace(emailPayload, workspacePayload)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testBitbucketProvider(bURL.Host, "bioinformatics", "")

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
}

func TestBitbucketProviderWorkspaceNotInList(t *testing.T) {
	emailPayload := `{"values": [ { "email": "michael.bland@gsa.gov", "is_primary": true } ] }`
	workspacePayload := `{"values": [
		{ "type": "workspace_access", "workspace": { "slug": "other-team-1" } },
		{ "type": "workspace_access", "workspace": { "slug": "other-team-2" } }
	]}`
	b := testBitbucketBackendWithWorkspace(emailPayload, workspacePayload)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testBitbucketProvider(bURL.Host, "bioinformatics", "")

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "", email)
}

func TestBitbucketProviderGetEmailAddressAndRepository(t *testing.T) {
	emailPayload := `{"values": [ { "email": "michael.bland@gsa.gov", "is_primary": true } ] }`
	repoPayload := `{"values": [ { "full_name": "bioinformatics/myrepo" } ] }`
	b := testBitbucketBackendFull(emailPayload, "", repoPayload)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testBitbucketProvider(bURL.Host, "", "bioinformatics/myrepo")

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
}

func TestBitbucketProviderGetEmailAddressMultipleRepositories(t *testing.T) {
	emailPayload := `{"values": [ { "email": "michael.bland@gsa.gov", "is_primary": true } ] }`
	// target repo is the last entry to exercise the full loop
	repoPayload := `{"values": [
		{ "full_name": "bioinformatics/other-repo-1" },
		{ "full_name": "bioinformatics/other-repo-2" },
		{ "full_name": "bioinformatics/myrepo" }
	]}`
	b := testBitbucketBackendFull(emailPayload, "", repoPayload)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testBitbucketProvider(bURL.Host, "", "bioinformatics/myrepo")

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
}

func TestBitbucketProviderRepositoryNotInList(t *testing.T) {
	emailPayload := `{"values": [ { "email": "michael.bland@gsa.gov", "is_primary": true } ] }`
	repoPayload := `{"values": [
		{ "full_name": "bioinformatics/other-repo-1" },
		{ "full_name": "bioinformatics/other-repo-2" }
	]}`
	b := testBitbucketBackendFull(emailPayload, "", repoPayload)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testBitbucketProvider(bURL.Host, "", "bioinformatics/myrepo")

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "", email)
}

// Note that trying to trigger the "failed building request" case is not
// practical, since the only way it can fail is if the URL fails to parse.
func TestBitbucketProviderGetEmailAddressFailedRequest(t *testing.T) {
	b := testBitbucketBackend("unused payload")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testBitbucketProvider(bURL.Host, "", "")

	// We'll trigger a request failure by using an unexpected access
	// token. Alternatively, we could allow the parsing of the payload as
	// JSON to fail.
	session := &sessions.SessionState{AccessToken: "unexpected_access_token"}
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}

func TestBitbucketProviderGetEmailAddressEmailNotPresentInPayload(t *testing.T) {
	b := testBitbucketBackend("{\"foo\": \"bar\"}")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testBitbucketProvider(bURL.Host, "", "")

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, "", email)
	assert.Equal(t, nil, err)
}

// ****************************************************************************
// Bitbucket Data Center (--bitbucket-datacenter-url)
// ****************************************************************************

const (
	bbdcTestToken    = "valid-token"
	bbdcTestUsername = "jdoe"
)

// testBitbucketDataCenterBackend fakes the subset of the Bitbucket Data Center
// REST / OAuth API the provider uses. contextPath simulates an instance served
// under a sub-path (e.g. /bitbucket). Only project PROJ and PROJ/repo are visible.
func testBitbucketDataCenterBackend(contextPath string) *httptest.Server {
	mux := http.NewServeMux()
	authed := func(r *http.Request) bool {
		return r.Header.Get("Authorization") == "Bearer "+bbdcTestToken
	}

	mux.HandleFunc(contextPath+"/rest/api/latest/application-properties", func(w http.ResponseWriter, r *http.Request) {
		// Anonymous access succeeds but carries no X-AUSERNAME, like the real thing.
		if authed(r) {
			w.Header().Set("X-AUSERNAME", bbdcTestUsername)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"version":"9.4.0"}`))
	})
	mux.HandleFunc(contextPath+"/rest/api/latest/users/"+bbdcTestUsername, func(w http.ResponseWriter, r *http.Request) {
		if !authed(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"name":"jdoe","slug":"jdoe","emailAddress":"jdoe@example.com","displayName":"J Doe","active":true}`))
	})
	mux.HandleFunc(contextPath+"/rest/api/latest/projects/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, contextPath+"/rest/api/latest/projects/")
		if !authed(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if path == "PROJ" || path == "PROJ/repos/repo" {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc(contextPath+"/rest/oauth2/latest/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Method != http.MethodPost || r.Form.Get("client_id") != "cid" || r.Form.Get("client_secret") != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.Form.Get("grant_type") {
		case "authorization_code":
			if r.Form.Get("code") != "the-code" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		case "refresh_token":
			if r.Form.Get("refresh_token") != "refresh-1" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		default:
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"` + bbdcTestToken + `","refresh_token":"refresh-1","expires_in":3600,"token_type":"bearer"}`))
	})
	return httptest.NewServer(mux)
}

func testBitbucketDataCenterProvider(opts options.BitbucketOptions) *BitbucketProvider {
	return NewBitbucketProvider(&ProviderData{ClientID: "cid", ClientSecret: "secret"}, opts)
}

func TestBitbucketDataCenterDefaults(t *testing.T) {
	p := testBitbucketDataCenterProvider(options.BitbucketOptions{DataCenterURL: "https://git.example.com/bitbucket/"})
	assert.Equal(t, "Bitbucket Data Center", p.Data().ProviderName)
	assert.Equal(t, "https://git.example.com/bitbucket/rest/oauth2/latest/authorize", p.Data().LoginURL.String())
	assert.Equal(t, "https://git.example.com/bitbucket/rest/oauth2/latest/token", p.Data().RedeemURL.String())
	assert.Equal(t, "https://git.example.com/bitbucket/rest/api/latest/application-properties", p.Data().ValidateURL.String())
	assert.Equal(t, "PUBLIC_REPOS", p.Data().Scope)
}

func TestBitbucketDataCenterScopeAdjust(t *testing.T) {
	p := testBitbucketDataCenterProvider(options.BitbucketOptions{
		DataCenterURL: "https://bitbucket.example.com",
		Workspace:     "PROJ",
		Repository:    "PROJ/repo",
	})
	// REPO_READ added once; Cloud scopes (account/repository) must not leak in.
	assert.Equal(t, "PUBLIC_REPOS REPO_READ", p.Data().Scope)
}

func TestBitbucketDataCenterGetEmailAddressNotImplemented(t *testing.T) {
	p := testBitbucketDataCenterProvider(options.BitbucketOptions{DataCenterURL: "https://bitbucket.example.com"})
	_, err := p.GetEmailAddress(context.Background(), &sessions.SessionState{AccessToken: bbdcTestToken})
	assert.Equal(t, ErrNotImplemented, err)
}

func TestBitbucketDataCenterRedeemAndRefresh(t *testing.T) {
	b := testBitbucketDataCenterBackend("")
	defer b.Close()
	p := testBitbucketDataCenterProvider(options.BitbucketOptions{DataCenterURL: b.URL})

	s, err := p.Redeem(context.Background(), "https://proxy/oauth2/callback", "the-code", "")
	assert.NoError(t, err)
	assert.Equal(t, bbdcTestToken, s.AccessToken)
	assert.Equal(t, "refresh-1", s.RefreshToken)
	assert.NotNil(t, s.ExpiresOn)

	refreshed, err := p.RefreshSession(context.Background(), s)
	assert.NoError(t, err)
	assert.True(t, refreshed)

	_, err = p.Redeem(context.Background(), "https://proxy/oauth2/callback", "bad-code", "")
	assert.Error(t, err)
}

func TestBitbucketDataCenterEnrichSession(t *testing.T) {
	b := testBitbucketDataCenterBackend("/bitbucket")
	defer b.Close()

	cases := map[string]struct {
		opts    options.BitbucketOptions
		token   string
		wantErr bool
	}{
		"no restrictions":            {token: bbdcTestToken},
		"allowed project":            {opts: options.BitbucketOptions{Workspace: "PROJ"}, token: bbdcTestToken},
		"denied project":             {opts: options.BitbucketOptions{Workspace: "NOPE"}, token: bbdcTestToken, wantErr: true},
		"allowed repository":         {opts: options.BitbucketOptions{Repository: "PROJ/repo"}, token: bbdcTestToken},
		"denied repository":          {opts: options.BitbucketOptions{Repository: "PROJ/other"}, token: bbdcTestToken, wantErr: true},
		"project and repository":     {opts: options.BitbucketOptions{Workspace: "PROJ", Repository: "PROJ/repo"}, token: bbdcTestToken},
		"project ok, repo denied":    {opts: options.BitbucketOptions{Workspace: "PROJ", Repository: "PROJ/other"}, token: bbdcTestToken, wantErr: true},
		"deprecated team as project": {opts: options.BitbucketOptions{Team: "PROJ"}, token: bbdcTestToken},
		"invalid token":              {token: "bad", wantErr: true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tc.opts.DataCenterURL = b.URL + "/bitbucket"
			p := testBitbucketDataCenterProvider(tc.opts)
			s := &sessions.SessionState{AccessToken: tc.token}
			err := p.EnrichSession(context.Background(), s)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, "jdoe", s.User)
			assert.Equal(t, "jdoe", s.PreferredUsername)
			assert.Equal(t, "jdoe@example.com", s.Email)
		})
	}
}

func TestBitbucketDataCenterValidateSession(t *testing.T) {
	b := testBitbucketDataCenterBackend("")
	defer b.Close()
	p := testBitbucketDataCenterProvider(options.BitbucketOptions{DataCenterURL: b.URL})

	assert.True(t, p.ValidateSession(context.Background(), &sessions.SessionState{AccessToken: bbdcTestToken}))
	assert.False(t, p.ValidateSession(context.Background(), &sessions.SessionState{AccessToken: "bad"}))
}

func TestBitbucketCloudEnrichSessionIsNoop(t *testing.T) {
	p := testBitbucketProvider("", "", "")
	s := &sessions.SessionState{AccessToken: "imaginary_access_token"}
	assert.NoError(t, p.EnrichSession(context.Background(), s))
	assert.Equal(t, "", s.User)
}
