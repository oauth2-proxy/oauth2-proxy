package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/stretchr/testify/assert"
)

const jsonParam = "f=json"

func testArcgisProvider(hostname string) *ArcgisProvider {
	p := NewArcgisProvider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
		})
	if hostname != "" {
		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		updateURL(p.Data().ProfileURL, hostname)
		updateURL(p.Data().ValidateURL, hostname)
	}
	return p
}

func testArcgisBackend() *httptest.Server {
	authResponse := `
		{
			"access_token": "my_access_token"
		 }
	`
	userInfo := `
		{
			"fullName": "Guinea Pig",
			"username": "guineapig",
			"email": "guineapig@email.com",
			"groups": [{
				"id": "abc"
			},{
				"id": "def"
			}]
		}
	`

	authHeader := "Bearer arcgis_access_token"

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/sharing/rest/oauth2/authorize":
				w.WriteHeader(200)
				w.Write([]byte(authResponse))
			case "/sharing/rest/community/self":
				if r.Header["Authorization"][0] == authHeader {
					w.WriteHeader(200)
					if r.URL.RawQuery == "f=json" {
						w.Write([]byte(userInfo))
					}
				} else {
					w.WriteHeader(401)
				}
			default:
				w.WriteHeader(200)
			}
		}))
}

func TestArcgisProviderDefaults(t *testing.T) {
	p := testArcgisProvider("")
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Arcgis", p.Data().ProviderName)
	assert.Equal(t, "https://www.arcgis.com/sharing/rest/oauth2/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://www.arcgis.com/sharing/rest/oauth2/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://www.arcgis.com/sharing/rest/community/self?"+jsonParam,
		p.Data().ValidateURL.String())
}

func TestArcgisProviderOverrides(t *testing.T) {
	p := NewArcgisProvider(
		&ProviderData{
			LoginURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/portal/sharing/rest/oauth2/authorize"},
			RedeemURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/portal/sharing/rest/oauth2/api/v1/token"},
			ValidateURL: &url.URL{
				Scheme:   "https",
				Host:     "example.com",
				Path:     "/portal/sharing/rest/community/self",
				RawQuery: jsonParam},
		})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Arcgis", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/portal/sharing/rest/oauth2/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/portal/sharing/rest/oauth2/api/v1/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://example.com/portal/sharing/rest/community/self?"+jsonParam,
		p.Data().ValidateURL.String())
}

func TestArcgisProviderEnrichSession(t *testing.T) {
	b := testArcgisBackend()
	bURL, err := url.Parse(b.URL)
	assert.Nil(t, err)
	p := testArcgisProvider(bURL.Host)
	session := &sessions.SessionState{AccessToken: "arcgis_access_token"}
	err = p.EnrichSession(context.Background(), session)
	assert.Equal(t, session.PreferredUsername, "Guinea Pig")
	assert.Equal(t, session.Email, "guineapig@email.com")
	assert.Equal(t, session.User, "guineapig")
	assert.Equal(t, len(session.Groups), 2)
	assert.Equal(t, session.Groups[0], "abc")
	assert.Equal(t, session.Groups[1], "def")
	assert.Nil(t, err)
	b.Close()
}

func TestArcgisProviderEnrichSessionFailsWithBadToken(t *testing.T) {
	b := testArcgisBackend()
	bURL, err := url.Parse(b.URL)
	assert.Nil(t, err)
	p := testArcgisProvider(bURL.Host)
	session := &sessions.SessionState{AccessToken: "unexpected_arcgis_access_token"}
	err = p.EnrichSession(context.Background(), session)
	assert.NotNil(t, err)
	b.Close()
}
