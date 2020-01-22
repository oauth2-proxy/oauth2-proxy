package providers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/stretchr/testify/assert"
)

const formatJSON = "format=json"
const userPath = "/ocs/v2.php/cloud/user"

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

func testNextcloudBackend(payload string) *httptest.Server {
	path := userPath
	query := formatJSON

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != path || r.URL.RawQuery != query {
				w.WriteHeader(404)
			} else if !IsAuthorizedInHeader(r.Header) {
				w.WriteHeader(403)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			}
		}))
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

func TestNextcloudProviderGetEmailAddress(t *testing.T) {
	b := testNextcloudBackend("{\"ocs\": {\"data\": { \"email\": \"michael.bland@gsa.gov\"}}}")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testNextcloudProvider(bURL.Host)
	p.ValidateURL.Path = userPath
	p.ValidateURL.RawQuery = formatJSON

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
}

// Note that trying to trigger the "failed building request" case is not
// practical, since the only way it can fail is if the URL fails to parse.
func TestNextcloudProviderGetEmailAddressFailedRequest(t *testing.T) {
	b := testNextcloudBackend("unused payload")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testNextcloudProvider(bURL.Host)
	p.ValidateURL.Path = userPath
	p.ValidateURL.RawQuery = formatJSON

	// We'll trigger a request failure by using an unexpected access
	// token. Alternatively, we could allow the parsing of the payload as
	// JSON to fail.
	session := &sessions.SessionState{AccessToken: "unexpected_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}

func TestNextcloudProviderGetEmailAddressEmailNotPresentInPayload(t *testing.T) {
	b := testNextcloudBackend("{\"foo\": \"bar\"}")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testNextcloudProvider(bURL.Host)
	p.ValidateURL.Path = userPath
	p.ValidateURL.RawQuery = formatJSON

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}
