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

func testBitbucketBackend(payloads map[string]string) *httptest.Server {
	paths := map[string]bool{
		"/2.0/user/emails": true,
		"/2.0/teams":       true,
	}

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			requestURL := r.URL
			payloadPath := requestURL.Path
			if strings.HasPrefix(requestURL.Path, "/2.0/repositories/") {
				payloadPath = "/2.0/repositories"
			}

			if !paths[requestURL.Path] && payloadPath != "/2.0/repositories" {
				log.Printf("%s not in %+v\n", requestURL.Path, paths)
				w.WriteHeader(404)
			} else if !IsAuthorizedInHeader(r.Header) || requestURL.Query().Get("access_token") != "" {
				w.WriteHeader(403)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payloads[payloadPath]))
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
	b := testBitbucketBackend(map[string]string{
		"/2.0/user/emails": "{\"values\": [ { \"email\": \"michael.bland@gsa.gov\", \"is_primary\": true } ] }",
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testBitbucketProvider(bURL.Host, "", "")

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
}

func TestBitbucketProviderGetEmailAddressAndGroup(t *testing.T) {
	b := testBitbucketBackend(map[string]string{
		"/2.0/user/emails": "{\"values\": [ { \"email\": \"michael.bland@gsa.gov\", \"is_primary\": true } ] }",
		"/2.0/teams":       "{\"values\": [ { \"username\": \"bioinformatics\" } ] }",
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testBitbucketProvider(bURL.Host, "bioinformatics", "")

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
}

func TestBitbucketProviderGetEmailAddressAndRepository(t *testing.T) {
	b := testBitbucketBackend(map[string]string{
		"/2.0/user/emails":  "{\"values\": [ { \"email\": \"michael.bland@gsa.gov\", \"is_primary\": true } ] }",
		"/2.0/repositories": "{\"values\": [ { \"full_name\": \"oauth2-proxy/oauth2-proxy\" } ] }",
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testBitbucketProvider(bURL.Host, "", "oauth2-proxy/oauth2-proxy")

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
}

// Note that trying to trigger the "failed building request" case is not
// practical, since the only way it can fail is if the URL fails to parse.
func TestBitbucketProviderGetEmailAddressFailedRequest(t *testing.T) {
	b := testBitbucketBackend(map[string]string{
		"/2.0/user/emails": "unused payload",
	})
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
	b := testBitbucketBackend(map[string]string{
		"/2.0/user/emails": "{\"foo\": \"bar\"}",
	})
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testBitbucketProvider(bURL.Host, "", "")

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, "", email)
	assert.Equal(t, nil, err)
}
