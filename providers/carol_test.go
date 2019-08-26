package providers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/stretchr/testify/assert"
)

func testCarolProvider(hostname string) *CarolProvider {
	p := NewCarolProvider(
		&ProviderData{
			ProviderName: "",
			ValidateURL:  &url.URL{}})
	if hostname != "" {
		updateURL(p.Data().ValidateURL, hostname)
	}
	return p
}

func testCarolBackend(token string) *httptest.Server {
	path := "/api/v2/oauth2/token/" + token

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != path {
				w.WriteHeader(404)
			} else {
				w.WriteHeader(200)
				//w.Write([]byte(payload))
			}
		}))
}

func TestCarolProviderDefaults(t *testing.T) {
	p := testCarolProvider("")
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Carol", p.Data().ProviderName)
	assert.Equal(t, "https://mendes.carol.ai/api/v2/oauth2/token/",
		p.Data().ValidateURL.String())
}

func TestCarolProviderOverrides(t *testing.T) {
	p := NewCarolProvider(
		&ProviderData{
			ValidateURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/api/v4/user"}})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Carol", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/api/v4/user",
		p.Data().ValidateURL.String())
}

func TestCarolProviderGetClientID(t *testing.T) {
	/*b := testCarolBackend("388ac910af1e11e9b5e142010a801029")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	logger.Printf(bURL.Host)*/
	//p := testCarolProvider(bURL.Host)
	p := testCarolProvider("mendes.carol.ai")
	//logger.Printf(bURL.Host)
	//logger.Printf(bURL.Path)

	session := &sessions.SessionState{AccessToken: "6a182fc0afa711e9a01342010a801fde"}
	clientID, err := p.GetClientID(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "8c35f1508b9a11e8abcbee82274893da_0a0829172fc2433c9aa26460c31b78f0_ab68f160967d11e893383e71b2508589_mdmConnector", clientID)
}

// Note that trying to trigger the "failed building request" case is not
// practical, since the only way it can fail is if the URL fails to parse.
func TestCarolProviderGetClientIDFailedRequest(t *testing.T) {
	b := testCarolBackend("unused payload")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testCarolProvider(bURL.Host)

	// We'll trigger a request failure by using an unexpected access
	// token. Alternatively, we could allow the parsing of the payload as
	// JSON to fail.
	session := &sessions.SessionState{AccessToken: "unexpected_access_token"}
	clientID, err := p.GetClientID(session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", clientID)
}

func TestCarolProviderGetClientIDNotPresentInPayload(t *testing.T) {
	b := testCarolBackend("{\"foo\": \"bar\"}")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testCarolProvider(bURL.Host)

	session := &sessions.SessionState{AccessToken: "imaginary_access_token"}
	clientID, err := p.GetClientID(session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", clientID)
}
