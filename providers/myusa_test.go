package providers

import (
	"github.com/bitly/go-simplejson"
	"github.com/bmizerany/assert"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func updateUrl(url *url.URL, hostname string) {
	url.Scheme = "http"
	url.Host = hostname
}

func testMyUsaProvider(hostname string) *MyUsaProvider {
	p := NewMyUsaProvider(
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

func testMyUsaBackend(payload string) *httptest.Server {
	path := "/api/v1/profile"
	query := "access_token=imaginary_access_token"

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			url := r.URL
			if url.Path != path || url.RawQuery != query {
				w.WriteHeader(404)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			}
		}))
}

func TestMyUsaProviderDefaults(t *testing.T) {
	p := testMyUsaProvider("")
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "MyUSA", p.Data().ProviderName)
	assert.Equal(t, "https://alpha.my.usa.gov/oauth/authorize",
		p.Data().LoginUrl.String())
	assert.Equal(t, "https://alpha.my.usa.gov/oauth/token",
		p.Data().RedeemUrl.String())
	assert.Equal(t, "https://alpha.my.usa.gov/api/v1/profile",
		p.Data().ProfileUrl.String())
	assert.Equal(t, "profile.email", p.Data().Scope)
}

func TestMyUsaProviderOverrides(t *testing.T) {
	p := NewMyUsaProvider(
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
	assert.Equal(t, "MyUSA", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/oauth/auth",
		p.Data().LoginUrl.String())
	assert.Equal(t, "https://example.com/oauth/token",
		p.Data().RedeemUrl.String())
	assert.Equal(t, "https://example.com/oauth/profile",
		p.Data().ProfileUrl.String())
	assert.Equal(t, "profile", p.Data().Scope)
}

func TestMyUsaProviderGetEmailAddress(t *testing.T) {
	b := testMyUsaBackend("{\"email\": \"michael.bland@gsa.gov\"}")
	defer b.Close()

	b_url, _ := url.Parse(b.URL)
	p := testMyUsaProvider(b_url.Host)
	unused_auth_response := simplejson.New()

	email, err := p.GetEmailAddress(unused_auth_response,
		"imaginary_access_token")
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
}

// Note that trying to trigger the "failed building request" case is not
// practical, since the only way it can fail is if the URL fails to parse.
func TestMyUsaProviderGetEmailAddressFailedRequest(t *testing.T) {
	b := testMyUsaBackend("unused payload")
	defer b.Close()

	b_url, _ := url.Parse(b.URL)
	p := testMyUsaProvider(b_url.Host)
	unused_auth_response := simplejson.New()

	// We'll trigger a request failure by using an unexpected access
	// token. Alternatively, we could allow the parsing of the payload as
	// JSON to fail.
	email, err := p.GetEmailAddress(unused_auth_response,
		"unexpected_access_token")
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}

func TestMyUsaProviderGetEmailAddressEmailNotPresentInPayload(t *testing.T) {
	b := testMyUsaBackend("{\"foo\": \"bar\"}")
	defer b.Close()

	b_url, _ := url.Parse(b.URL)
	p := testMyUsaProvider(b_url.Host)
	unused_auth_response := simplejson.New()

	email, err := p.GetEmailAddress(unused_auth_response,
		"imaginary_access_token")
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}
