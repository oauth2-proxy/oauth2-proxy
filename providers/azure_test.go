package providers

import (
	"fmt"
	"github.com/bmizerany/assert"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

var (
	path_group            string = "/v1.0/me/memberOf?$select=displayName"
	path_group_next       string = "/v1.0/me/memberOf?$select=displayName&$skiptoken=X%27test-token%27"
	path_group_wrong      string = "/v1.0/him/memberOf?$select=displayName"
	payload_group_empty   string = `{"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#directoryObjects(displayName)","value":[]}`
	payload_group_garbage string = `{"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#directoryObjects(displayName)","value":[{"@odata.type":"#microsoft.graph.group","displayName":"test-group-1"},{"@odata.type":"#microsoft.graph.group","displayName":"test-group-2"}]}`
	payload_group_simple  string = `{"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#directoryObjects(displayName)","value":[{"@odata.type":"#microsoft.graph.group","displayName":"test-group-1"},{"@odata.type":"#microsoft.graph.group","displayName":"test-group-2"}]}`
	payload_group_part_1  string = `{"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#directoryObjects(displayName)","@odata.nextLink":"https://graph.microsoft.com/v1.0/me/memberOf?$select=displayName&$skiptoken=X%27test-token%27","value":[{"@odata.type":"#microsoft.graph.group","displayName":"test-group-1"},{"@odata.type":"#microsoft.graph.group","displayName":"test-group-2"}]}`
	payload_group_part_2  string = `{"@odata.context":"https://graph.microsoft.com/v1.0/$metadata#directoryObjects(displayName)","value":[{"@odata.type":"#microsoft.graph.group","displayName":"test-group-3"}]}`
)

type mockTransport struct {
	params map[string]string
}

func (t *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	log.Printf("Starting Round Tripper")
	// Create mocked http.Response
	response := &http.Response{
		Header:     make(http.Header),
		Request:    req,
		StatusCode: http.StatusOK,
	}
	response.Header.Set("Content-Type", "application/json")

	//url := req.URL
	full_request := req.URL.Path
	if req.URL.RawQuery != "" {
		full_request += "?" + req.URL.RawQuery
	}
	var err error
	if value, ok := t.params[full_request]; ok {
		if req.Header.Get("Authorization") != "Bearer imaginary_access_token" {
			response.StatusCode = http.StatusForbidden
			err = fmt.Errorf("got 403. Bearer token '%v' is not correct", req.Header.Get("Authorization"))
		} else {
			response.StatusCode = http.StatusOK
			response.Body = ioutil.NopCloser(strings.NewReader(value))
			err = nil
		}

	} else {
		response.StatusCode = http.StatusNotFound
		err = fmt.Errorf("got 404. Requested path '%v' is not found", full_request)
	}

	return response, err
}

func newMockTransport(params map[string]string) http.RoundTripper {
	return &mockTransport{params}
}

func testAzureProvider(hostname string) *AzureProvider {
	p := NewAzureProvider(
		&ProviderData{
			ProviderName:      "",
			LoginURL:          &url.URL{},
			RedeemURL:         &url.URL{},
			ProfileURL:        &url.URL{},
			ValidateURL:       &url.URL{},
			ProtectedResource: &url.URL{},
			Scope:             ""})

	if hostname != "" {
		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		updateURL(p.Data().ProfileURL, hostname)
		updateURL(p.Data().ValidateURL, hostname)
		updateURL(p.Data().ProtectedResource, hostname)
	}
	return p
}

func TestAzureProviderDefaults(t *testing.T) {
	p := testAzureProvider("")
	assert.NotEqual(t, nil, p)
	p.Configure("")
	assert.Equal(t, "Azure", p.Data().ProviderName)
	assert.Equal(t, "common", p.Tenant)
	assert.Equal(t, "https://login.microsoftonline.com/common/oauth2/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://login.microsoftonline.com/common/oauth2/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://graph.microsoft.com/v1.0/me",
		p.Data().ProfileURL.String())
	assert.Equal(t, "https://graph.microsoft.com",
		p.Data().ProtectedResource.String())
	assert.Equal(t, "",
		p.Data().ValidateURL.String())
	assert.Equal(t, "openid", p.Data().Scope)
}

func TestAzureProviderOverrides(t *testing.T) {
	p := NewAzureProvider(
		&ProviderData{
			LoginURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/auth"},
			RedeemURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/token"},
			ProfileURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/profile"},
			ValidateURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/tokeninfo"},
			ProtectedResource: &url.URL{
				Scheme: "https",
				Host:   "example.com"},
			Scope: "profile"})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Azure", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/oauth/auth",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://example.com/oauth/profile",
		p.Data().ProfileURL.String())
	assert.Equal(t, "https://example.com/oauth/tokeninfo",
		p.Data().ValidateURL.String())
	assert.Equal(t, "https://example.com",
		p.Data().ProtectedResource.String())
	assert.Equal(t, "profile", p.Data().Scope)
}

func TestAzureSetTenant(t *testing.T) {
	p := testAzureProvider("")
	p.Configure("example")
	assert.Equal(t, "Azure", p.Data().ProviderName)
	assert.Equal(t, "example", p.Tenant)
	assert.Equal(t, "https://login.microsoftonline.com/example/oauth2/authorize",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://login.microsoftonline.com/example/oauth2/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://graph.microsoft.com/v1.0/me",
		p.Data().ProfileURL.String())
	assert.Equal(t, "https://graph.microsoft.com",
		p.Data().ProtectedResource.String())
	assert.Equal(t, "",
		p.Data().ValidateURL.String())
	assert.Equal(t, "openid", p.Data().Scope)
}

func testAzureBackend(payload string) *httptest.Server {
	path := "/v1.0/me"
	query := ""

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			url := r.URL
			if url.Path != path || url.RawQuery != query {
				w.WriteHeader(404)
			} else if r.Header.Get("Authorization") != "Bearer imaginary_access_token" {
				w.WriteHeader(403)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			}
		}))
}

func TestAzureProviderGetEmailAddress(t *testing.T) {
	b := testAzureBackend(`{ "mail": "user@windows.net" }`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testAzureProvider(bURL.Host)

	session := &SessionState{AccessToken: "imaginary_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "user@windows.net", email)
}

func TestAzureProviderGetEmailAddressMailNull(t *testing.T) {
	b := testAzureBackend(`{ "mail": null, "otherMails": ["user@windows.net", "altuser@windows.net"] }`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testAzureProvider(bURL.Host)

	session := &SessionState{AccessToken: "imaginary_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "user@windows.net", email)
}

func TestAzureProviderGetEmailAddressGetUserPrincipalName(t *testing.T) {
	b := testAzureBackend(`{ "mail": null, "otherMails": [], "userPrincipalName": "user@windows.net" }`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testAzureProvider(bURL.Host)

	session := &SessionState{AccessToken: "imaginary_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "user@windows.net", email)
}

func TestAzureProviderGetEmailAddressFailToGetEmailAddress(t *testing.T) {
	b := testAzureBackend(`{ "mail": null, "otherMails": [], "userPrincipalName": null }`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testAzureProvider(bURL.Host)

	session := &SessionState{AccessToken: "imaginary_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, "type assertion to string failed", err.Error())
	assert.Equal(t, "", email)
}

func TestAzureProviderGetEmailAddressEmptyUserPrincipalName(t *testing.T) {
	b := testAzureBackend(`{ "mail": null, "otherMails": [], "userPrincipalName": "" }`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testAzureProvider(bURL.Host)

	session := &SessionState{AccessToken: "imaginary_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "", email)
}

func TestAzureProviderGetEmailAddressIncorrectOtherMails(t *testing.T) {
	b := testAzureBackend(`{ "mail": null, "otherMails": "", "userPrincipalName": null }`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testAzureProvider(bURL.Host)

	session := &SessionState{AccessToken: "imaginary_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, "type assertion to string failed", err.Error())
	assert.Equal(t, "", email)
}

func TestAzureProviderNoGroups(t *testing.T) {
	params := map[string]string{
		path_group: payload_group_empty}

	http.DefaultClient.Transport = newMockTransport(params)

	p := testAzureProvider("")

	session := &SessionState{
		AccessToken: "imaginary_access_token",
		IDToken:     "imaginary_IDToken_token"}

	groups, err := p.GetGroups(session, "")
	http.DefaultClient.Transport = nil

	assert.Equal(t, nil, err)
	assert.Equal(t, "", groups)
}

func TestAzureProviderWrongRequestGroups(t *testing.T) {
	params := map[string]string{
		path_group_wrong: payload_group_part_1}
	http.DefaultClient.Transport = newMockTransport(params)
	log.Printf("Def %#v\n\n", http.DefaultClient.Transport)

	p := testAzureProvider("")

	session := &SessionState{
		AccessToken: "imaginary_access_token",
		IDToken:     "imaginary_IDToken_token"}

	groups, err := p.GetGroups(session, "")
	http.DefaultClient.Transport = nil

	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", groups)
}

func TestAzureProviderMultiRequestsGroups(t *testing.T) {
	params := map[string]string{
		path_group:      payload_group_part_1,
		path_group_next: payload_group_part_2}
	http.DefaultClient.Transport = newMockTransport(params)

	p := testAzureProvider("")

	session := &SessionState{
		AccessToken: "imaginary_access_token",
		IDToken:     "imaginary_IDToken_token"}

	groups, err := p.GetGroups(session, "")
	http.DefaultClient.Transport = nil

	assert.Equal(t, nil, err)
	assert.Equal(t, "test-group-1|test-group-2|test-group-3", groups)
}

func TestAzureEmptyPermittedGroups(t *testing.T) {
	p := testAzureProvider("")

	session := &SessionState{
		AccessToken: "imaginary_access_token",
		IDToken:     "imaginary_IDToken_token",
		Groups:      "no one|cares|non existing|groups"}
	result := p.ValidateGroup(session)

	assert.Equal(t, true, result)
}

func TestAzureWrongPermittedGroups(t *testing.T) {
	p := testAzureProvider("")
	p.SetGroupRestriction([]string{"test-group-2"})

	session := &SessionState{
		AccessToken: "imaginary_access_token",
		IDToken:     "imaginary_IDToken_token",
		Groups:      "no one|cares|non existing|groups|test-group-1"}
	result := p.ValidateGroup(session)

	assert.Equal(t, false, result)
}

func TestAzureRightPermittedGroups(t *testing.T) {
	p := testAzureProvider("")
	p.SetGroupRestriction([]string{"test-group-1", "test-group-2"})

	session := &SessionState{
		AccessToken: "imaginary_access_token",
		IDToken:     "imaginary_IDToken_token",
		Groups:      "no one|cares|test-group-2|non existing|groups"}
	result := p.ValidateGroup(session)

	assert.Equal(t, true, result)
}
