package providers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func testAuth0Provider(domain string) *Auth0Provider {
	p := NewAuth0Provider(
		&ProviderData{
			ApprovalPrompt:    "approvalPrompt",
			ClientID:          "clientID",
			LoginURL:          &url.URL{},
			RedeemURL:         &url.URL{},
			ProfileURL:        &url.URL{},
			ValidateURL:       &url.URL{},
			ProtectedResource: &url.URL{},
		})
	p.Configure(domain)
	p.LoginURL.Scheme = "http"
	p.RedeemURL.Scheme = "http"
	p.ProfileURL.Scheme = "http"
	p.ValidateURL.Scheme = "http"
	return p
}

func TestAuth0ProviderDefaults(t *testing.T) {
	p := testAuth0Provider("example.auth0.com")

	assert.Equal(t, "Auth0", p.Data().ProviderName)
	assert.Equal(t, "example.auth0.com", p.Domain)
	assert.Equal(t, "http://example.auth0.com/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "http://example.auth0.com/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "http://example.auth0.com/userinfo",
		p.Data().ProfileURL.String())
	assert.Equal(t, "",
		p.Data().ProtectedResource.String())
	assert.Equal(t, "http://example.auth0.com/userinfo",
		p.Data().ValidateURL.String())
	assert.Equal(t, "openid profile email", p.Data().Scope)
}

func TestAuth0GetLoginUrl(t *testing.T) {
	p := testAuth0Provider("example.auth0.com")

	actual := p.GetLoginURL("http://localhost:1234", "state")
	assert.Equal(t, "http://example.auth0.com/authorize?"+
		"approval_prompt=approvalPrompt"+
		"&client_id=clientID"+
		"&redirect_uri=http%3A%2F%2Flocalhost%3A1234"+
		"&response_type=code"+
		"&scope=openid+profile+email"+
		"&state=state",
		actual)
}

func testAuth0Backend(payload string) *httptest.Server {
	path := "/userinfo"

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != path && r.Method != "GET" {
				w.WriteHeader(404)
			} else if r.Method == "GET" && r.Body == nil {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			} else if !IsAuthorizedInHeader(r.Header) {
				w.WriteHeader(403)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			}
		}))
}

func TestAuth0ProviderGetEmailAddress(t *testing.T) {
	b := testAuth0Backend(`{ "email": "test@auth0.com" }`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testAuth0Provider(bURL.Host)

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "test@auth0.com", email)
}

func TestAuth0ProviderGetEmailAddressFailedRequest(t *testing.T) {
	b := testAuth0Backend("unused payload")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testAuth0Provider(bURL.Host)

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}

func TestAuth0ProviderGetEmailAddressEmailNotPresentInPayload(t *testing.T) {
	b := testAuth0Backend(`{ "foo": "bar" }`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testAuth0Provider(bURL.Host)

	session := CreateAuthorizedSession()
	email, err := p.GetEmailAddress(session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}
