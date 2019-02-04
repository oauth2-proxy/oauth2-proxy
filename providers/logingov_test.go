package providers

import (
	// "encoding/base64"
	// "encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

type loginGovRedeemResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token"`
}

func newLoginGovRedeemServer(body []byte) (*url.URL, *httptest.Server) {
	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Write(body)
	}))
	u, _ := url.Parse(s.URL)
	return u, s
}

func newLoginGovProvider() *LoginGovProvider {
	return NewLoginGovProvider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""})
}

func TestLoginGovProviderDefaults(t *testing.T) {
	p := newLoginGovProvider()
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "login.gov", p.Data().ProviderName)
	assert.Equal(t, "https://secure.login.gov/openid_connect/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://secure.login.gov/api/openid_connect/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://secure.login.gov/api/openid_connect/userinfo",
		p.Data().ProfileURL.String())
	assert.Equal(t, "email openid", p.Data().Scope)
}

func TestLoginGovProviderOverrides(t *testing.T) {
	p := NewLoginGovProvider(
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
	assert.Equal(t, "login.gov", p.Data().ProviderName)
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

// XXX make more real tests here!
