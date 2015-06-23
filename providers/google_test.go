package providers

import (
	"encoding/base64"
	"encoding/json"
	"github.com/bmizerany/assert"
	"net/url"
	"testing"
)

func newGoogleProvider() *GoogleProvider {
	return NewGoogleProvider(
		&ProviderData{
			ProviderName: "",
			LoginUrl:     &url.URL{},
			RedeemUrl:    &url.URL{},
			ProfileUrl:   &url.URL{},
			ValidateUrl:  &url.URL{},
			Scope:        ""})
}

func TestGoogleProviderDefaults(t *testing.T) {
	p := newGoogleProvider()
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Google", p.Data().ProviderName)
	assert.Equal(t, "https://accounts.google.com/o/oauth2/auth?access_type=offline",
		p.Data().LoginUrl.String())
	assert.Equal(t, "https://www.googleapis.com/oauth2/v3/token",
		p.Data().RedeemUrl.String())
	assert.Equal(t, "https://www.googleapis.com/oauth2/v1/tokeninfo",
		p.Data().ValidateUrl.String())
	assert.Equal(t, "", p.Data().ProfileUrl.String())
	assert.Equal(t, "profile email", p.Data().Scope)
}

func TestGoogleProviderOverrides(t *testing.T) {
	p := NewGoogleProvider(
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
			ValidateUrl: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/tokeninfo"},
			Scope: "profile"})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Google", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/oauth/auth",
		p.Data().LoginUrl.String())
	assert.Equal(t, "https://example.com/oauth/token",
		p.Data().RedeemUrl.String())
	assert.Equal(t, "https://example.com/oauth/profile",
		p.Data().ProfileUrl.String())
	assert.Equal(t, "https://example.com/oauth/tokeninfo",
		p.Data().ValidateUrl.String())
	assert.Equal(t, "profile", p.Data().Scope)
}

func TestGoogleProviderGetEmailAddress(t *testing.T) {
	p := newGoogleProvider()
	body, err := json.Marshal(
		struct {
			IdToken string `json:"id_token"`
		}{
			IdToken: "ignored prefix." + base64.URLEncoding.EncodeToString([]byte(`{"email": "michael.bland@gsa.gov"}`)),
		},
	)
	assert.Equal(t, nil, err)
	email, err := p.GetEmailAddress(body, "ignored access_token")
	assert.Equal(t, "michael.bland@gsa.gov", email)
	assert.Equal(t, nil, err)
}

func TestGoogleProviderGetEmailAddressInvalidEncoding(t *testing.T) {
	p := newGoogleProvider()
	body, err := json.Marshal(
		struct {
			IdToken string `json:"id_token"`
		}{
			IdToken: "ignored prefix." + `{"email": "michael.bland@gsa.gov"}`,
		},
	)
	assert.Equal(t, nil, err)
	email, err := p.GetEmailAddress(body, "ignored access_token")
	assert.Equal(t, "", email)
	assert.NotEqual(t, nil, err)
}

func TestGoogleProviderGetEmailAddressInvalidJson(t *testing.T) {
	p := newGoogleProvider()

	body, err := json.Marshal(
		struct {
			IdToken string `json:"id_token"`
		}{
			IdToken: "ignored prefix." + base64.URLEncoding.EncodeToString([]byte(`{"email": michael.bland@gsa.gov}`)),
		},
	)
	assert.Equal(t, nil, err)
	email, err := p.GetEmailAddress(body, "ignored access_token")
	assert.Equal(t, "", email)
	assert.NotEqual(t, nil, err)
}

func TestGoogleProviderGetEmailAddressEmailMissing(t *testing.T) {
	p := newGoogleProvider()
	body, err := json.Marshal(
		struct {
			IdToken string `json:"id_token"`
		}{
			IdToken: "ignored prefix." + base64.URLEncoding.EncodeToString([]byte(`{"not_email": "missing"}`)),
		},
	)
	assert.Equal(t, nil, err)
	email, err := p.GetEmailAddress(body, "ignored access_token")
	assert.Equal(t, "", email)
	assert.NotEqual(t, nil, err)
}
