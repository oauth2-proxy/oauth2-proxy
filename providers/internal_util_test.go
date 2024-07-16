package providers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/stretchr/testify/assert"
)

func updateURL(url *url.URL, hostname string) {
	if url == nil {
		return
	}
	url.Scheme = "http"
	url.Host = hostname
}

type ValidateSessionTestProvider struct {
	*ProviderData
}

var _ Provider = (*ValidateSessionTestProvider)(nil)

func (tp *ValidateSessionTestProvider) GetEmailAddress(_ context.Context, _ *sessions.SessionState) (string, error) {
	return "", errors.New("not implemented")
}

// Note that we're testing the internal validateToken() used to implement
// several Provider's ValidateSession() implementations
func (tp *ValidateSessionTestProvider) ValidateSession(_ context.Context, _ *sessions.SessionState) bool {
	return false
}

type ValidateSessionStateTest struct {
	backend      *httptest.Server
	responseCode int
	provider     *ValidateSessionTestProvider
	header       http.Header
}

func NewValidateSessionTest() *ValidateSessionStateTest {
	var vtTest ValidateSessionStateTest

	vtTest.backend = httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/oauth/tokeninfo" {
				w.WriteHeader(500)
				w.Write([]byte("unknown URL"))
			}
			tokenParam := r.FormValue("access_token")
			if tokenParam == "" {
				missing := false
				receivedHeaders := r.Header
				for k := range vtTest.header {
					received := receivedHeaders.Get(k)
					expected := vtTest.header.Get(k)
					if received == "" || received != expected {
						missing = true
					}
				}
				if missing {
					w.WriteHeader(500)
					w.Write([]byte("no token param and missing or incorrect headers"))
				}
			}
			w.WriteHeader(vtTest.responseCode)
			w.Write([]byte("only code matters; contents disregarded"))

		}))
	backendURL, _ := url.Parse(vtTest.backend.URL)
	vtTest.provider = &ValidateSessionTestProvider{
		ProviderData: &ProviderData{
			ValidateURL: &url.URL{
				Scheme: "http",
				Host:   backendURL.Host,
				Path:   "/oauth/tokeninfo",
			},
		},
	}
	vtTest.responseCode = 200
	return &vtTest
}

func (vtTest *ValidateSessionStateTest) Close() {
	vtTest.backend.Close()
}

func TestValidateSessionValidToken(t *testing.T) {
	vtTest := NewValidateSessionTest()
	defer vtTest.Close()
	assert.Equal(t, true, validateToken(context.Background(), vtTest.provider, "foobar", nil))
}

func TestValidateSessionValidTokenWithHeaders(t *testing.T) {
	vtTest := NewValidateSessionTest()
	defer vtTest.Close()
	vtTest.header = make(http.Header)
	vtTest.header.Set("Authorization", "Bearer foobar")
	assert.Equal(t, true,
		validateToken(context.Background(), vtTest.provider, "foobar", vtTest.header))
}

func TestValidateSessionEmptyToken(t *testing.T) {
	vtTest := NewValidateSessionTest()
	defer vtTest.Close()
	assert.Equal(t, false, validateToken(context.Background(), vtTest.provider, "", nil))
}

func TestValidateSessionEmptyValidateURL(t *testing.T) {
	vtTest := NewValidateSessionTest()
	defer vtTest.Close()
	vtTest.provider.Data().ValidateURL = nil
	assert.Equal(t, false, validateToken(context.Background(), vtTest.provider, "foobar", nil))
}

func TestValidateSessionRequestNetworkFailure(t *testing.T) {
	vtTest := NewValidateSessionTest()
	// Close immediately to simulate a network failure
	vtTest.Close()
	assert.Equal(t, false, validateToken(context.Background(), vtTest.provider, "foobar", nil))
}

func TestValidateSessionExpiredToken(t *testing.T) {
	vtTest := NewValidateSessionTest()
	defer vtTest.Close()
	vtTest.responseCode = 401
	assert.Equal(t, false, validateToken(context.Background(), vtTest.provider, "foobar", nil))
}

func TestValidateSessionValidateURLWithQueryParams(t *testing.T) {
	vtTest := NewValidateSessionTest()
	defer vtTest.Close()
	vtTest.provider.Data().ValidateURL, _ = url.Parse(vtTest.provider.Data().ValidateURL.String() + "?query_param1=true&query_param2=test")
	assert.Equal(t, true, validateToken(context.Background(), vtTest.provider, "foobar", nil))
}

func TestStripTokenNotPresent(t *testing.T) {
	test := "http://local.test/api/test?a=1&b=2"
	assert.Equal(t, test, stripToken(test))
}

func TestStripToken(t *testing.T) {
	test := "http://local.test/api/test?access_token=deadbeef&b=1&c=2"
	expected := "http://local.test/api/test?access_token=dead...&b=1&c=2"
	assert.Equal(t, expected, stripToken(test))
}
