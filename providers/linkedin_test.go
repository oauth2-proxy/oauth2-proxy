package providers

import (
	"github.com/bitly/go-simplejson"
	"github.com/bmizerany/assert"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func testLinkedInProvider(hostname string) *LinkedInProvider {
	p := NewLinkedInProvider(
		&ProviderData{
			ProviderName: "",
			LoginUrl:     &url.URL{},
			RedeemUrl:    &url.URL{},
			ProfileUrl:   &url.URL{},
			Scope:        ""})
	if hostname != "" {
		updateUrl(p.Data().LoginUrl, hostname)
		updateUrl(p.Data().RedeemUrl, hostname)
		updateUrl(p.Data().ProfileUrl, hostname)
	}
	return p
}

func testLinkedInBackend(payload string) *httptest.Server {
	path := "/v1/people/~/email-address"

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			url := r.URL
			if url.Path != path {
				w.WriteHeader(404)
			} else if r.Header.Get("Authorization") != "Bearer imaginary_access_token" {
				w.WriteHeader(403)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			}
		}))
}

func TestLinkedInProviderDefaults(t *testing.T) {
	p := testLinkedInProvider("")
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "LinkedIn", p.Data().ProviderName)
	assert.Equal(t, "https://www.linkedin.com/uas/oauth2/authorization",
		p.Data().LoginUrl.String())
	assert.Equal(t, "https://www.linkedin.com/uas/oauth2/accessToken",
		p.Data().RedeemUrl.String())
	assert.Equal(t, "https://www.linkedin.com/v1/people/~/email-address",
		p.Data().ProfileUrl.String())
	assert.Equal(t, "r_emailaddress r_basicprofile", p.Data().Scope)
}

func TestLinkedInProviderOverrides(t *testing.T) {
	p := NewLinkedInProvider(
		&ProviderData{
			LoginUrl: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/auth"},
			RedeemUrl: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/token"},
			ProfileUrl: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/profile"},
			Scope: "profile"})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "LinkedIn", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/oauth/auth",
		p.Data().LoginUrl.String())
	assert.Equal(t, "https://example.com/oauth/token",
		p.Data().RedeemUrl.String())
	assert.Equal(t, "https://example.com/oauth/profile",
		p.Data().ProfileUrl.String())
	assert.Equal(t, "profile", p.Data().Scope)
}

func TestLinkedInProviderGetEmailAddress(t *testing.T) {
	b := testLinkedInBackend(`"user@linkedin.com"`)
	defer b.Close()

	b_url, _ := url.Parse(b.URL)
	p := testLinkedInProvider(b_url.Host)
	unused_auth_response := simplejson.New()

	email, err := p.GetEmailAddress(unused_auth_response,
		"imaginary_access_token")
	assert.Equal(t, nil, err)
	assert.Equal(t, "user@linkedin.com", email)
}

func TestLinkedInProviderGetEmailAddressFailedRequest(t *testing.T) {
	b := testLinkedInBackend("unused payload")
	defer b.Close()

	b_url, _ := url.Parse(b.URL)
	p := testLinkedInProvider(b_url.Host)
	unused_auth_response := simplejson.New()

	// We'll trigger a request failure by using an unexpected access
	// token. Alternatively, we could allow the parsing of the payload as
	// JSON to fail.
	email, err := p.GetEmailAddress(unused_auth_response,
		"unexpected_access_token")
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}

func TestLinkedInProviderGetEmailAddressEmailNotPresentInPayload(t *testing.T) {
	b := testLinkedInBackend("{\"foo\": \"bar\"}")
	defer b.Close()

	b_url, _ := url.Parse(b.URL)
	p := testLinkedInProvider(b_url.Host)
	unused_auth_response := simplejson.New()

	email, err := p.GetEmailAddress(unused_auth_response,
		"imaginary_access_token")
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}
