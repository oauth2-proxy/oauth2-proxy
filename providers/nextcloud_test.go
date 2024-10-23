package providers

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

const formatJSON = "format=json"

func testNextcloudProvider(hostname string) *NextcloudProvider {
	p := NewNextcloudProvider(
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
		updateURL(p.Data().ValidateURL, hostname)
	}
	return p
}

func TestNextcloudProviderDefaults(t *testing.T) {
	p := testNextcloudProvider("")
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Nextcloud", p.Data().ProviderName)
	assert.Equal(t, "",
		p.Data().LoginURL.String())
	assert.Equal(t, "",
		p.Data().RedeemURL.String())
	assert.Equal(t, "",
		p.Data().ValidateURL.String())
}

func TestNextcloudProviderOverrides(t *testing.T) {
	p := NewNextcloudProvider(
		&ProviderData{
			LoginURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/index.php/apps/oauth2/authorize"},
			RedeemURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/index.php/apps/oauth2/api/v1/token"},
			ValidateURL: &url.URL{
				Scheme:   "https",
				Host:     "example.com",
				Path:     "/test/ocs/v2.php/cloud/user",
				RawQuery: formatJSON},
			Scope: "profile"})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Nextcloud", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/index.php/apps/oauth2/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/index.php/apps/oauth2/api/v1/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://example.com/test/ocs/v2.php/cloud/user?"+formatJSON,
		p.Data().ValidateURL.String())
}
