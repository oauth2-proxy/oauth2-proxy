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

func testLinkedInProvider(hostname string) *LinkedInProvider {
	p := NewLinkedInProvider(
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
	}
	return p
}

func testLinkedInBackend(payload string) *httptest.Server {
	path := "/v1/people/~/email-address"

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != path {
				w.WriteHeader(404)
			} else if !IsAuthorizedInHeader(r.Header) {
				w.WriteHeader(403)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			}
		}))
}

func TestNewLinkedInProvider(t *testing.T) {
	g := NewWithT(t)

	// Test that defaults are set when calling for a new provider with nothing set
	providerData := NewLinkedInProvider(&ProviderData{}).Data()
	g.Expect(providerData.ProviderName).To(Equal("LinkedIn"))
	g.Expect(providerData.LoginURL.String()).To(Equal("https://www.linkedin.com/uas/oauth2/authorization"))
	g.Expect(providerData.RedeemURL.String()).To(Equal("https://www.linkedin.com/uas/oauth2/accessToken"))
	g.Expect(providerData.ProfileURL.String()).To(Equal("https://www.linkedin.com/v1/people/~/email-address"))
	g.Expect(providerData.ValidateURL.String()).To(Equal("https://www.linkedin.com/v1/people/~/email-address"))
	g.Expect(providerData.Scope).To(Equal("r_emailaddress r_basicprofile"))
}

func TestLinkedInProviderOverrides(t *testing.T) {
	p := NewLinkedInProvider(
		&ProviderData{
			LoginURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/auth"},
			RedeemURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/token"},
			ProfileURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/profile"},
			ValidateURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/tokeninfo"},
			Scope: "profile"})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "LinkedIn", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/oauth/auth",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://example.com/oauth/profile",
		p.Data().ProfileURL.String())
	assert.Equal(t, "https://example.com/oauth/tokeninfo",
		p.Data().ValidateURL.String())
	assert.Equal(t, "profile", p.Data().Scope)
}

func TestLinkedInProviderGetEmailAddress(t *testing.T) {
	b := testLinkedInBackend(`"user@linkedin.com"`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testLinkedInProvider(bURL.Host)

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "user@linkedin.com", email)
}

func TestLinkedInProviderGetEmailAddressFailedRequest(t *testing.T) {
	b := testLinkedInBackend("unused payload")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testLinkedInProvider(bURL.Host)

	// We'll trigger a request failure by using an unexpected access
	// token. Alternatively, we could allow the parsing of the payload as
	// JSON to fail.
	session := &sessions.SessionState{AccessToken: "unexpected_access_token"}
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}

func TestLinkedInProviderGetEmailAddressEmailNotPresentInPayload(t *testing.T) {
	b := testLinkedInBackend("{\"foo\": \"bar\"}")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testLinkedInProvider(bURL.Host)

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(context.Background(), session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}
