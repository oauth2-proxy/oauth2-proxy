package providers

import (
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
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
			Scope:        ""})

	if team != "" {
		p.SetTeam(team)
	}

	if repository != "" {
		p.SetRepository(repository)
	}

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
		"/2.0/teams":       true,
	}

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			url := r.URL
			if !paths[url.Path] {
				log.Printf("%s not in %+v\n", url.Path, paths)
				w.WriteHeader(404)
			} else if !IsAuthorizedInURL(r.URL) {
				w.WriteHeader(403)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			}
		}))
}

func TestNewBitbucketProvider(t *testing.T) {
	g := NewWithT(t)

	// Test that defaults are set when calling for a new provider with nothing set
	providerData := NewBitbucketProvider(&ProviderData{}).Data()
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
	assert.Equal(t, "email team", p.Data().Scope)
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
			Scope: "profile"})
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
	b := testBitbucketBackend("{\"values\": [ { \"email\": \"michael.bland@gsa.gov\", \"is_primary\": true, \"username\": \"bioinformatics\" } ] }")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testBitbucketProvider(bURL.Host, "bioinformatics", "")

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
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
