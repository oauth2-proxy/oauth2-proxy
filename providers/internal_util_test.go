package providers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/bmizerany/assert"
)

type ValidateSessionStateTestProvider struct {
	*ProviderData
}

func (tp *ValidateSessionStateTestProvider) GetEmailAddress(s *SessionState) (string, error) {
	return "", errors.New("not implemented")
}

// Note that we're testing the internal validateToken() used to implement
// several Provider's ValidateSessionState() implementations
func (tp *ValidateSessionStateTestProvider) ValidateSessionState(s *SessionState) bool {
	return false
}

type ValidateSessionStateTest struct {
	backend       *httptest.Server
	response_code int
	provider      *ValidateSessionStateTestProvider
	header        http.Header
}

func NewValidateSessionStateTest() *ValidateSessionStateTest {
	var vt_test ValidateSessionStateTest

	vt_test.backend = httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/oauth/tokeninfo" {
				w.WriteHeader(500)
				w.Write([]byte("unknown URL"))
			}
			token_param := r.FormValue("access_token")
			if token_param == "" {
				missing := false
				received_headers := r.Header
				for k, _ := range vt_test.header {
					received := received_headers.Get(k)
					expected := vt_test.header.Get(k)
					if received == "" || received != expected {
						missing = true
					}
				}
				if missing {
					w.WriteHeader(500)
					w.Write([]byte("no token param and missing or incorrect headers"))
				}
			}
			w.WriteHeader(vt_test.response_code)
			w.Write([]byte("only code matters; contents disregarded"))

		}))
	backend_url, _ := url.Parse(vt_test.backend.URL)
	vt_test.provider = &ValidateSessionStateTestProvider{
		ProviderData: &ProviderData{
			ValidateURL: &url.URL{
				Scheme: "http",
				Host:   backend_url.Host,
				Path:   "/oauth/tokeninfo",
			},
		},
	}
	vt_test.response_code = 200
	return &vt_test
}

func (vt_test *ValidateSessionStateTest) Close() {
	vt_test.backend.Close()
}

func TestValidateSessionStateValidToken(t *testing.T) {
	vt_test := NewValidateSessionStateTest()
	defer vt_test.Close()
	assert.Equal(t, true, validateToken(vt_test.provider, "foobar", nil))
}

func TestValidateSessionStateValidTokenWithHeaders(t *testing.T) {
	vt_test := NewValidateSessionStateTest()
	defer vt_test.Close()
	vt_test.header = make(http.Header)
	vt_test.header.Set("Authorization", "Bearer foobar")
	assert.Equal(t, true,
		validateToken(vt_test.provider, "foobar", vt_test.header))
}

func TestValidateSessionStateEmptyToken(t *testing.T) {
	vt_test := NewValidateSessionStateTest()
	defer vt_test.Close()
	assert.Equal(t, false, validateToken(vt_test.provider, "", nil))
}

func TestValidateSessionStateEmptyValidateURL(t *testing.T) {
	vt_test := NewValidateSessionStateTest()
	defer vt_test.Close()
	vt_test.provider.Data().ValidateURL = nil
	assert.Equal(t, false, validateToken(vt_test.provider, "foobar", nil))
}

func TestValidateSessionStateRequestNetworkFailure(t *testing.T) {
	vt_test := NewValidateSessionStateTest()
	// Close immediately to simulate a network failure
	vt_test.Close()
	assert.Equal(t, false, validateToken(vt_test.provider, "foobar", nil))
}

func TestValidateSessionStateExpiredToken(t *testing.T) {
	vt_test := NewValidateSessionStateTest()
	defer vt_test.Close()
	vt_test.response_code = 401
	assert.Equal(t, false, validateToken(vt_test.provider, "foobar", nil))
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
