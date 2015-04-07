package main

import (
	"github.com/bitly/go-simplejson"
	"github.com/bitly/google_auth_proxy/providers"
	"github.com/bmizerany/assert"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestNewReverseProxy(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		hostname, _, _ := net.SplitHostPort(r.Host)
		w.Write([]byte(hostname))
	}))
	defer backend.Close()

	backendURL, _ := url.Parse(backend.URL)
	backendHostname, backendPort, _ := net.SplitHostPort(backendURL.Host)
	backendHost := net.JoinHostPort(backendHostname, backendPort)
	proxyURL, _ := url.Parse(backendURL.Scheme + "://" + backendHost + "/")

	proxyHandler := NewReverseProxy(proxyURL)
	setProxyUpstreamHostHeader(proxyHandler, proxyURL)
	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()

	getReq, _ := http.NewRequest("GET", frontend.URL, nil)
	res, _ := http.DefaultClient.Do(getReq)
	bodyBytes, _ := ioutil.ReadAll(res.Body)
	if g, e := string(bodyBytes), backendHostname; g != e {
		t.Errorf("got body %q; expected %q", g, e)
	}
}

func TestEncodedSlashes(t *testing.T) {
	var seen string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		seen = r.RequestURI
	}))
	defer backend.Close()

	b, _ := url.Parse(backend.URL)
	proxyHandler := NewReverseProxy(b)
	setProxyDirector(proxyHandler)
	frontend := httptest.NewServer(proxyHandler)
	defer frontend.Close()

	f, _ := url.Parse(frontend.URL)
	encodedPath := "/a%2Fb/?c=1"
	getReq := &http.Request{URL: &url.URL{Scheme: "http", Host: f.Host, Opaque: encodedPath}}
	_, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("err %s", err)
	}
	if seen != encodedPath {
		t.Errorf("got bad request %q expected %q", seen, encodedPath)
	}
}

type TestProvider struct {
	*providers.ProviderData
	EmailAddress string
}

func (tp *TestProvider) GetEmailAddress(unused_auth_response *simplejson.Json,
	unused_access_token string) (string, error) {
	return tp.EmailAddress, nil
}

type PassAccessTokenTest struct {
	provider_server *httptest.Server
	proxy           *OauthProxy
	opts            *Options
}

type PassAccessTokenTestOptions struct {
	PassAccessToken bool
}

func NewPassAccessTokenTest(opts PassAccessTokenTestOptions) *PassAccessTokenTest {
	t := &PassAccessTokenTest{}

	t.provider_server = httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			url := r.URL
			payload := ""
			switch url.Path {
			case "/oauth/token":
				payload = `{"access_token": "my_auth_token"}`
			default:
				token_header := r.Header["X-Forwarded-Access-Token"]
				if len(token_header) != 0 {
					payload = token_header[0]
				} else {
					payload = "No access token found."
				}
			}
			w.WriteHeader(200)
			w.Write([]byte(payload))
		}))

	t.opts = NewOptions()
	t.opts.Upstreams = append(t.opts.Upstreams, t.provider_server.URL)
	// The CookieSecret must be 32 bytes in order to create the AES
	// cipher.
	t.opts.CookieSecret = "xyzzyplughxyzzyplughxyzzyplughxp"
	t.opts.ClientID = "bazquux"
	t.opts.ClientSecret = "foobar"
	t.opts.CookieSecure = false
	t.opts.PassAccessToken = opts.PassAccessToken
	t.opts.Validate()

	provider_url, _ := url.Parse(t.provider_server.URL)
	const email_address = "michael.bland@gsa.gov"

	t.opts.provider = &TestProvider{
		ProviderData: &providers.ProviderData{
			ProviderName: "Test Provider",
			LoginUrl: &url.URL{
				Scheme: "http",
				Host:   provider_url.Host,
				Path:   "/oauth/authorize",
			},
			RedeemUrl: &url.URL{
				Scheme: "http",
				Host:   provider_url.Host,
				Path:   "/oauth/token",
			},
			ProfileUrl: &url.URL{
				Scheme: "http",
				Host:   provider_url.Host,
				Path:   "/api/v1/profile",
			},
			Scope: "profile.email",
		},
		EmailAddress: email_address,
	}

	t.proxy = NewOauthProxy(t.opts, func(email string) bool {
		return email == email_address
	})
	return t
}

func (pat_test *PassAccessTokenTest) Close() {
	pat_test.provider_server.Close()
}

func (pat_test *PassAccessTokenTest) getCallbackEndpoint() (http_code int,
	cookie string) {
	rw := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/oauth2/callback?code=callback_code",
		strings.NewReader(""))
	if err != nil {
		return 0, ""
	}
	pat_test.proxy.ServeHTTP(rw, req)
	return rw.Code, rw.HeaderMap["Set-Cookie"][0]
}

func (pat_test *PassAccessTokenTest) getRootEndpoint(
	cookie string) (http_code int, access_token string) {
	cookie_key := pat_test.proxy.CookieKey
	var value string
	key_prefix := cookie_key + "="

	for _, field := range strings.Split(cookie, "; ") {
		value = strings.TrimPrefix(field, key_prefix)
		if value != field {
			break
		} else {
			value = ""
		}
	}
	if value == "" {
		return 0, ""
	}

	req, err := http.NewRequest("GET", "/", strings.NewReader(""))
	if err != nil {
		return 0, ""
	}
	req.AddCookie(&http.Cookie{
		Name:     cookie_key,
		Value:    value,
		Path:     "/",
		Expires:  time.Now().Add(time.Duration(24)),
		HttpOnly: true,
	})

	rw := httptest.NewRecorder()
	pat_test.proxy.ServeHTTP(rw, req)
	return rw.Code, rw.Body.String()
}

func TestForwardAccessTokenUpstream(t *testing.T) {
	pat_test := NewPassAccessTokenTest(PassAccessTokenTestOptions{
		PassAccessToken: true,
	})
	defer pat_test.Close()

	// A successful validation will redirect and set the auth cookie.
	code, cookie := pat_test.getCallbackEndpoint()
	assert.Equal(t, 302, code)
	assert.NotEqual(t, nil, cookie)

	// Now we make a regular request; the access_token from the cookie is
	// forwarded as the "X-Forwarded-Access-Token" header. The token is
	// read by the test provider server and written in the response body.
	code, payload := pat_test.getRootEndpoint(cookie)
	assert.Equal(t, 200, code)
	assert.Equal(t, "my_auth_token", payload)
}

func TestDoNotForwardAccessTokenUpstream(t *testing.T) {
	pat_test := NewPassAccessTokenTest(PassAccessTokenTestOptions{
		PassAccessToken: false,
	})
	defer pat_test.Close()

	// A successful validation will redirect and set the auth cookie.
	code, cookie := pat_test.getCallbackEndpoint()
	assert.Equal(t, 302, code)
	assert.NotEqual(t, nil, cookie)

	// Now we make a regular request, but the access token header should
	// not be present.
	code, payload := pat_test.getRootEndpoint(cookie)
	assert.Equal(t, 200, code)
	assert.Equal(t, "No access token found.", payload)
}

type SignInPageTest struct {
	opts           *Options
	proxy          *OauthProxy
	sign_in_regexp *regexp.Regexp
}

const signInRedirectPattern = `<input type="hidden" name="rd" value="(.*)">`

func NewSignInPageTest() *SignInPageTest {
	var sip_test SignInPageTest

	sip_test.opts = NewOptions()
	sip_test.opts.Upstreams = append(sip_test.opts.Upstreams, "unused")
	sip_test.opts.CookieSecret = "foobar"
	sip_test.opts.ClientID = "bazquux"
	sip_test.opts.ClientSecret = "xyzzyplugh"
	sip_test.opts.Validate()

	sip_test.proxy = NewOauthProxy(sip_test.opts, func(email string) bool {
		return true
	})
	sip_test.sign_in_regexp = regexp.MustCompile(signInRedirectPattern)

	return &sip_test
}

func (sip_test *SignInPageTest) GetEndpoint(endpoint string) (int, string) {
	rw := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", endpoint, strings.NewReader(""))
	sip_test.proxy.ServeHTTP(rw, req)
	return rw.Code, rw.Body.String()
}

func TestSignInPageIncludesTargetRedirect(t *testing.T) {
	sip_test := NewSignInPageTest()
	const endpoint = "/some/random/endpoint"

	code, body := sip_test.GetEndpoint(endpoint)
	assert.Equal(t, 403, code)

	match := sip_test.sign_in_regexp.FindStringSubmatch(body)
	if match == nil {
		t.Fatal("Did not find pattern in body: " +
			signInRedirectPattern + "\nBody:\n" + body)
	}
	if match[1] != endpoint {
		t.Fatal(`expected redirect to "` + endpoint +
			`", but was "` + match[1] + `"`)
	}
}

func TestSignInPageDirectAccessRedirectsToRoot(t *testing.T) {
	sip_test := NewSignInPageTest()
	code, body := sip_test.GetEndpoint("/oauth2/sign_in")
	assert.Equal(t, 200, code)

	match := sip_test.sign_in_regexp.FindStringSubmatch(body)
	if match == nil {
		t.Fatal("Did not find pattern in body: " +
			signInRedirectPattern + "\nBody:\n" + body)
	}
	if match[1] != "/" {
		t.Fatal(`expected redirect to "/", but was "` + match[1] + `"`)
	}
}
