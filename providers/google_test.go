package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	admin "google.golang.org/api/admin/directory/v1"
	option "google.golang.org/api/option"
)

func newRedeemServer(body []byte) (*url.URL, *httptest.Server) {
	s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Write(body)
	}))
	u, _ := url.Parse(s.URL)
	return u, s
}

func newGoogleProvider() *GoogleProvider {
	return NewGoogleProvider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""})
}

func TestGoogleProviderDefaults(t *testing.T) {
	p := newGoogleProvider()
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Google", p.Data().ProviderName)
	assert.Equal(t, "https://accounts.google.com/o/oauth2/auth?access_type=offline",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://www.googleapis.com/oauth2/v3/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://www.googleapis.com/oauth2/v1/tokeninfo",
		p.Data().ValidateURL.String())
	assert.Equal(t, "", p.Data().ProfileURL.String())
	assert.Equal(t, "profile email", p.Data().Scope)
}

func TestGoogleProviderOverrides(t *testing.T) {
	p := NewGoogleProvider(
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
			Scope: "profile"})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Google", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/oauth/auth",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://example.com/oauth/profile",
		p.Data().ProfileURL.String())
	assert.Equal(t, "https://example.com/oauth/tokeninfo",
		p.Data().ValidateURL.String())
	assert.Equal(t, "profile", p.Data().Scope)
}

type redeemResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token"`
}

func TestGoogleProviderGetEmailAddress(t *testing.T) {
	p := newGoogleProvider()
	body, err := json.Marshal(redeemResponse{
		AccessToken:  "a1234",
		ExpiresIn:    10,
		RefreshToken: "refresh12345",
		IDToken:      "ignored prefix." + base64.URLEncoding.EncodeToString([]byte(`{"email": "michael.bland@gsa.gov", "email_verified":true}`)),
	})
	assert.Equal(t, nil, err)
	var server *httptest.Server
	p.RedeemURL, server = newRedeemServer(body)
	defer server.Close()

	session, err := p.Redeem("http://redirect/", "code1234")
	assert.Equal(t, nil, err)
	assert.NotEqual(t, session, nil)
	assert.Equal(t, "michael.bland@gsa.gov", session.Email)
	assert.Equal(t, "a1234", session.AccessToken)
	assert.Equal(t, "refresh12345", session.RefreshToken)
}

func TestGoogleProviderValidateGroup(t *testing.T) {
	p := newGoogleProvider()
	p.GroupValidator = func(email string) bool {
		return email == "michael.bland@gsa.gov"
	}
	assert.Equal(t, true, p.ValidateGroup("michael.bland@gsa.gov"))
	p.GroupValidator = func(email string) bool {
		return email != "michael.bland@gsa.gov"
	}
	assert.Equal(t, false, p.ValidateGroup("michael.bland@gsa.gov"))
}

func TestGoogleProviderWithoutValidateGroup(t *testing.T) {
	p := newGoogleProvider()
	assert.Equal(t, true, p.ValidateGroup("michael.bland@gsa.gov"))
}

//
func TestGoogleProviderGetEmailAddressInvalidEncoding(t *testing.T) {
	p := newGoogleProvider()
	body, err := json.Marshal(redeemResponse{
		AccessToken: "a1234",
		IDToken:     "ignored prefix." + `{"email": "michael.bland@gsa.gov"}`,
	})
	assert.Equal(t, nil, err)
	var server *httptest.Server
	p.RedeemURL, server = newRedeemServer(body)
	defer server.Close()

	session, err := p.Redeem("http://redirect/", "code1234")
	assert.NotEqual(t, nil, err)
	if session != nil {
		t.Errorf("expect nill session %#v", session)
	}
}

func TestGoogleProviderGetEmailAddressInvalidJson(t *testing.T) {
	p := newGoogleProvider()

	body, err := json.Marshal(redeemResponse{
		AccessToken: "a1234",
		IDToken:     "ignored prefix." + base64.URLEncoding.EncodeToString([]byte(`{"email": michael.bland@gsa.gov}`)),
	})
	assert.Equal(t, nil, err)
	var server *httptest.Server
	p.RedeemURL, server = newRedeemServer(body)
	defer server.Close()

	session, err := p.Redeem("http://redirect/", "code1234")
	assert.NotEqual(t, nil, err)
	if session != nil {
		t.Errorf("expect nill session %#v", session)
	}

}

func TestGoogleProviderGetEmailAddressEmailMissing(t *testing.T) {
	p := newGoogleProvider()
	body, err := json.Marshal(redeemResponse{
		AccessToken: "a1234",
		IDToken:     "ignored prefix." + base64.URLEncoding.EncodeToString([]byte(`{"not_email": "missing"}`)),
	})
	assert.Equal(t, nil, err)
	var server *httptest.Server
	p.RedeemURL, server = newRedeemServer(body)
	defer server.Close()

	session, err := p.Redeem("http://redirect/", "code1234")
	assert.NotEqual(t, nil, err)
	if session != nil {
		t.Errorf("expect nill session %#v", session)
	}

}

func TestGoogleProviderUserInGroup(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/groups/group@example.com/hasMember/member-in-domain@example.com" {
			fmt.Fprintln(w, `{"isMember": true}`)
		} else if r.URL.Path == "/groups/group@example.com/hasMember/non-member-in-domain@example.com" {
			fmt.Fprintln(w, `{"isMember": false}`)
		} else if r.URL.Path == "/groups/group@example.com/hasMember/member-out-of-domain@otherexample.com" {
			http.Error(
				w,
				`{"error": {"errors": [{"domain": "global","reason": "invalid","message": "Invalid Input: memberKey"}],"code": 400,"message": "Invalid Input: memberKey"}}`,
				http.StatusBadRequest,
			)
		} else if r.URL.Path == "/groups/group@example.com/hasMember/non-member-out-of-domain@otherexample.com" {
			http.Error(
				w,
				`{"error": {"errors": [{"domain": "global","reason": "invalid","message": "Invalid Input: memberKey"}],"code": 400,"message": "Invalid Input: memberKey"}}`,
				http.StatusBadRequest,
			)
		} else if r.URL.Path == "/groups/group@example.com/members/non-member-out-of-domain@otherexample.com" {
			// note that the client currently doesn't care what this response text or code is - any error here results in failure to match the group
			http.Error(
				w,
				`{"error": {"errors": [{"domain": "global","reason": "notFound","message": "Resource Not Found: memberKey"}],"code": 404,"message": "Resource Not Found: memberKey"}}`,
				http.StatusNotFound,
			)
		} else if r.URL.Path == "/groups/group@example.com/members/member-out-of-domain@otherexample.com" {
			fmt.Fprintln(w,
				`{"kind": "admin#directory#member","etag":"12345","id":"1234567890","email": "member-out-of-domain@otherexample.com","role": "MEMBER","type": "USER","status": "ACTIVE","delivery_settings": "ALL_MAIL"}}`,
			)
		}
	}))
	defer ts.Close()

	client := ts.Client()
	ctx := context.Background()

	service, err := admin.NewService(ctx, option.WithHTTPClient(client))
	service.BasePath = ts.URL
	assert.Equal(t, nil, err)

	result := userInGroup(service, []string{"group@example.com"}, "member-in-domain@example.com")
	assert.True(t, result)

	result = userInGroup(service, []string{"group@example.com"}, "member-out-of-domain@otherexample.com")
	assert.True(t, result)

	result = userInGroup(service, []string{"group@example.com"}, "non-member-in-domain@example.com")
	assert.False(t, result)

	result = userInGroup(service, []string{"group@example.com"}, "non-member-out-of-domain@otherexample.com")
	assert.False(t, result)
}
