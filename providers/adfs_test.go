package providers

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

type redeemResponseADFS struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token"`
}

func newADFSRedeemServer(body []byte) (*url.URL, *httptest.Server) {
	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Write(body)
	}))
	u, _ := url.Parse(s.URL)
	return u, s
}

func newADFSProvider() *ADFSProvider {
	return NewADFSProvider(
		&ProviderData{
			ProviderName:      "",
			LoginURL:          &url.URL{},
			RedeemURL:         &url.URL{},
			ProtectedResource: &url.URL{},
			Scope:             ""})
}

func TestADFSProviderDefaults(t *testing.T) {
	p := newADFSProvider()
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "ADFS", p.Data().ProviderName)
	assert.Equal(t, "", p.Data().LoginURL.String())
	assert.Equal(t, "", p.Data().RedeemURL.String())
	assert.Equal(t, "", p.Data().ProtectedResource.String())
	assert.Equal(t, "openid", p.Data().Scope)
}

func TestADFSProviderGetEmailAddressAndUpn(t *testing.T) {
	p := newADFSProvider()
	body, err := json.Marshal(redeemResponseADFS{
		AccessToken:  "test12345",
		ExpiresIn:    10,
		RefreshToken: "refreshtest12345",
		IDToken:      "jwt header." + base64.URLEncoding.EncodeToString([]byte(`{"upn": "m_fedotov@gmail.com", "email": "m_fedotov@gmail.com"}`)),
	})
	assert.Equal(t, nil, err)
	var server *httptest.Server
	p.RedeemURL, server = newADFSRedeemServer(body)
	defer server.Close()

	session, err := p.Redeem("http://redirect/", "code1234")
	assert.Equal(t, nil, err)
	assert.NotEqual(t, session, nil)
	assert.Equal(t, "m_fedotov@gmail.com", session.Email)
	assert.Equal(t, "test12345", session.AccessToken)
	assert.Equal(t, "refreshtest12345", session.RefreshToken)
	assert.Equal(t, "m_fedotov@gmail.com", session.User)
}

func TestADFSProviderGetUpnOnly(t *testing.T) {
	p := newADFSProvider()
	body, err := json.Marshal(redeemResponseADFS{
		AccessToken:  "test12345",
		ExpiresIn:    10,
		RefreshToken: "refreshtest12345",
		IDToken:      "jwt header." + base64.URLEncoding.EncodeToString([]byte(`{"upn": "m_fedotov@gmail.com"}`)),
	})
	assert.Equal(t, nil, err)
	var server *httptest.Server
	p.RedeemURL, server = newADFSRedeemServer(body)
	defer server.Close()

	session, err := p.Redeem("http://redirect/", "code1234")
	assert.Equal(t, nil, err)
	assert.NotEqual(t, session, nil)
	assert.Equal(t, "m_fedotov@gmail.com", session.Email)
	assert.Equal(t, "test12345", session.AccessToken)
	assert.Equal(t, "refreshtest12345", session.RefreshToken)
	assert.Equal(t, "m_fedotov@gmail.com", session.User)
}
