package providers

import (
	"encoding/base64"
	"github.com/bitly/go-simplejson"
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
			Scope:        ""})
}

func TestGoogleProviderDefaults(t *testing.T) {
	p := newGoogleProvider()
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Google", p.Data().ProviderName)
	assert.Equal(t, "https://accounts.google.com/o/oauth2/auth",
		p.Data().LoginUrl.String())
	assert.Equal(t, "https://accounts.google.com/o/oauth2/token",
		p.Data().RedeemUrl.String())
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
			Scope: "profile"})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Google", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/oauth/auth",
		p.Data().LoginUrl.String())
	assert.Equal(t, "https://example.com/oauth/token",
		p.Data().RedeemUrl.String())
	assert.Equal(t, "https://example.com/oauth/profile",
		p.Data().ProfileUrl.String())
	assert.Equal(t, "profile", p.Data().Scope)
}

func TestGoogleProviderGetEmailAddress(t *testing.T) {
	p := newGoogleProvider()
	j := simplejson.New()
	j.Set("id_token", "ignored prefix."+base64.URLEncoding.EncodeToString(
		[]byte("{\"email\": \"michael.bland@gsa.gov\"}")))
	email, err := p.GetEmailAddress(j, "ignored access_token")
	assert.Equal(t, "michael.bland@gsa.gov", email)
	assert.Equal(t, nil, err)
}

func TestGoogleProviderGetEmailAddressInvalidEncoding(t *testing.T) {
	p := newGoogleProvider()
	j := simplejson.New()
	j.Set("id_token", "ignored prefix.{\"email\": \"michael.bland@gsa.gov\"}")
	email, err := p.GetEmailAddress(j, "ignored access_token")
	assert.Equal(t, "", email)
	assert.NotEqual(t, nil, err)
}

func TestGoogleProviderGetEmailAddressInvalidJson(t *testing.T) {
	p := newGoogleProvider()
	j := simplejson.New()
	j.Set("id_token", "ignored prefix."+base64.URLEncoding.EncodeToString(
		[]byte("{email: michael.bland@gsa.gov}")))
	email, err := p.GetEmailAddress(j, "ignored access_token")
	assert.Equal(t, "", email)
	assert.NotEqual(t, nil, err)
}

func TestGoogleProviderGetEmailAddressEmailMissing(t *testing.T) {
	p := newGoogleProvider()
	j := simplejson.New()
	j.Set("id_token", "ignored prefix."+base64.URLEncoding.EncodeToString(
		[]byte("{\"not_email\": \"missing!\"}")))
	email, err := p.GetEmailAddress(j, "ignored access_token")
	assert.Equal(t, "", email)
	assert.NotEqual(t, nil, err)
}
