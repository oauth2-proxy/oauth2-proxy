package providers

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/stretchr/testify/assert"
)

var exampleIDToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImxWOEtHUjlhbTVrU0VoYkZfemozT2JMZHZQNkZkYUMyWGctU0lvdFNlc2sifQ.eyJqdGkiOiIxZjBkNTIxZC1jZTRmLTRjODMtOGE4Mi1lZWMzY2JlOTE1YjkiLCJleHAiOjE1NzEzOTk3NDksIm5iZiI6MCwiaWF0IjoxNTcxMzk2MTQ5LCJpc3MiOiJodHRwczovL29hdXRoMi1wcm94eS5pc3N1ZXIubmV0IiwiYXVkIjoic3NvIiwic3ViIjoib2F1dGgyLXByb3h5LXVzZXIiLCJ0eXAiOiJJRCIsImF6cCI6InNzbyIsImF1dGhfdGltZSI6MTU3MTM5NjE0OSwic2Vzc2lvbl9zdGF0ZSI6ImQ5MjkyMWM2LTZmNTUtNDdlZS04OWFiLWUxN2FhNTQ5MzhhZiIsImFjciI6IjEiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6Ik9hdXRoMiBQcm94eSIsInByZWZlcnJlZF91c2VybmFtZSI6Im9hdXRoMi1wcm94eSIsImdpdmVuX25hbWUiOiJPYXV0aDIiLCJmYW1pbHlfbmFtZSI6IlByb3h5IiwiZW1haWwiOiJvYXV0aDIucHJveHlAb2F1dGgyLXByb3h5LmNvbSJ9.bHrvjbWugNvEk-rUmY5LLc5rVfOBogd8fDgJBDacvSsKI2Htzac8tPcjsSjw-asrKlP7eRP_Pq4bW_GXqe3Y8vBbWHxtPL3iBArZknkPkI-gYgObCbqIA7X43HGFFEdcg66ASfAfyvW7wyxTG67VMwSU_sFnP5dm3Akt47DSRhuCxih-IZjmmnTf-sio3yrLKkE3-wb7gyhkkZu9pdpbr4ayQALWEzRE7I_F-PmRBR2Vqsd5TGN6MDlds6BdpIf-_GIH67AHErTFJjwMYuRN4Ekw-sTQdk3J1I5kkqplvP4LbzObhb6yEHfB0TqtMSUN9uKsDjY3DBjkGoOsdUJdNdF8Q60wnO1F_zhwR4MKcaGMQu_vgv1uKJZNr9jTR3jS3CfoXLU67zL5HDLtiezmS0_7fam7amaWma9oU0daFlxwRgzCEiy-gRF3luzQZUy66bTykBsLQbwTbRwIU-Tz0wY0U2jwMrA9HCjnxh8Fad4jHvT5yBxp7gBWMXCxf7PG2vBtEb8sMgK62QzmqhALaf3TP00rY3xtzpZgTrNZgadLx2S4nqodYa66LY12n8__TpklpAsr0pYRDFyKeaqo_bBSMdhgIyCHQkvMKEl_aRTWjwsnBvOhqNrCb8sD4Gv8ln5safY2fj0QQR1rH-eDYNJ9KUHW_sAPaHx7BN17Dy0"
var exampleAccessToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImxWOEtHUjlhbTVrU0VoYkZfemozT2JMZHZQNkZkYUMyWGctU0lvdFNlc2sifQ.eyJqdGkiOiI0N2ZkMjkzNS1lMTc0LTRjODgtYmY2OS0yNmI0NzQ2MDY1OTAiLCJleHAiOjE1NzE0MDAyNzAsIm5iZiI6MCwiaWF0IjoxNTcxMzk2NjcwLCJpc3MiOiJodHRwczovL29hdXRoMi1wcm94eS5pc3N1ZXIubmV0IiwiYXVkIjoic3NvIiwic3ViIjoiYWRiYjM5OWItZmI3MS00MTJkLWJmYzgtYjE3ZTQ3YzAyMjU4IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoidGVzdCIsImF1dGhfdGltZSI6MCwic2Vzc2lvbl9zdGF0ZSI6ImFhZjU4YTJkLWJmNDEtNDkyMC1iODkwLTA1ZjU0YzczZjQxMSIsImFjciI6IjEiLCJzY29wZSI6ImVtYWlsIHByb2ZpbGUiLCJjbGllbnRIb3N0IjoiMTAuNTYuNTUuMjEwIiwicHJlZmVycmVkX3VzZXJuYW1lIjoib2F1dGgyLXByb3h5IiwiY2xpZW50QWRkcmVzcyI6IjEwLjU2LjU1LjIxMCIsImVtYWlsIjoib2F1dGgyLnByb3h5QG9hdXRoMi1wcm94eS5jb20ifQ.vnHU6skiyQJ--bmuZszsgkGcVWtvh_AjyAFOkB0eSQqXCu0uLShr2svCxXiSV5Ikv8ZsFK9suc3fpDsN1etI-oUYRLdocEIlEvpK05SnDwR72Edh99YUccTNu7ALZ-7cRZyQrI4HExdvA8Jr5SAQ9ORdrF9kkEW-A4tuaJ8ZeShQDKqBn9-e5XRmQCMbfKANFC5wTOjQ3hiJ4ovQkcBFAuHfolgGS6DuykDRjyU25T5pE6IKFU-UGfdZ18Vmkf92yeyN-vPrxlHU6Hg8G1rO2WQuiyqCtKnaI9IuFI3Mp7oFfCu64cgf6fvJgr6Q7r2C4M-efg8lndsAhNhH-XD_EgnGXPHyy2TIg5xDX4Iv9K1p7Snz0lCwGXDioz0cgUdllp_6KgrNjcvDQTRNgEXHLdSnV7njZDwpIaQh1_O5sTHFQ9e7RYWoMqcO_0mdB12ZqV1s978RpYodJPX4W8tnypC9JAt7XypllgEgJXPG3oknCWpfEqJKZoG5hXKllmI8VFg0YpfhXFECDqRXubeFg14TM43TpMPueyujGmMieKvsRp4nln_TRzEChG0Ro3ii_H2i1f13v-H2gBQS2ZtjRhQkiuAQSieAHfNbedcovnsP1GAJXonchgErv85x94DHlmg45j3lpqV8NxCl4Nn7oRaCDxas-XtfWvVrm7I6yNk"
var exampleRefreshToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjY2MmVkZWI2LWRiM2MtNDYxZS1hNjY0LTlkMTNjOWY2MzI2MCJ9.eyJqdGkiOiJjNTAwNTUwYS1hMDg4LTRkN2EtODFjMy1iZWEyMjViMmNjNjAiLCJleHAiOjE1NzEzOTg0NzAsIm5iZiI6MCwiaWF0IjoxNTcxMzk2NjcwLCJpc3MiOiJodHRwczovL29hdXRoMi1wcm94eS5pc3N1ZXIubmV0IiwiYXVkIjoic3NvIiwic3ViIjoiYWRiYjM5OWItZmI3MS00MTJkLWJmYzgtYjE3ZTQ3YzAyMjU4IiwidHlwIjoiUmVmcmVzaCIsImF6cCI6InRlc3QiLCJhdXRoX3RpbWUiOjAsInNlc3Npb25fc3RhdGUiOiJhYWY1OGEyZC1iZjQxLTQ5MjAtYjg5MC0wNWY1NGM3M2Y0MTEiLCJzY29wZSI6ImVtYWlsIHByb2ZpbGUifQ.AufhD7Wy1EhaiASnocfGbivriVg3fuq3oKrcyjdhhb0"

type NoOpKeySet struct {
}

func (NoOpKeySet) VerifySignature(ctx context.Context, jwt string) (payload []byte, err error) {
	splitStrings := strings.Split(jwt, ".")
	payloadString := splitStrings[1]
	jsonString, err := base64.RawURLEncoding.DecodeString(payloadString)
	return []byte(jsonString), err
}

var keyset = NoOpKeySet{}
var verifier = oidc.NewVerifier("https://oauth2-proxy.issuer.net", keyset,
	&oidc.Config{ClientID: "sso", SkipExpiryCheck: true})

func testAzureProvider(hostname string) *AzureProvider {
	p := NewAzureProvider(
		&ProviderData{
			ClientID:          "AzureClient",
			ClientSecret:      "AzureClientSecret",
			ProviderName:      "",
			LoginURL:          &url.URL{},
			RedeemURL:         &url.URL{},
			ProfileURL:        &url.URL{},
			ValidateURL:       &url.URL{},
			ProtectedResource: &url.URL{},
			Scope:             ""})
	p.Verifier = verifier
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
	assert.Equal(t, "https://graph.windows.net/me?api-version=1.6",
		p.Data().ProfileURL.String())
	assert.Equal(t, "https://graph.windows.net",
		p.Data().ProtectedResource.String())
	assert.Equal(t, "https://graph.windows.net/me?api-version=1.6",
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
	assert.Equal(t, "https://graph.windows.net/me?api-version=1.6",
		p.Data().ProfileURL.String())
	assert.Equal(t, "https://graph.windows.net",
		p.Data().ProtectedResource.String())
	assert.Equal(t, "https://graph.windows.net/me?api-version=1.6",
		p.Data().ValidateURL.String())
	assert.Equal(t, "openid", p.Data().Scope)
}

func testAzureBackend(payload string) *httptest.Server {
	path := "/me"
	query := "api-version=1.6"

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if (r.URL.Path != path || r.URL.RawQuery != query) && r.Method != "POST" {
				w.WriteHeader(404)
			} else if r.Method == "POST" && r.Body != nil {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			} else if r.Header.Get("Authorization") != "Bearer imaginary_access_token" {
				w.WriteHeader(403)
			} else {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(200)
				w.Write([]byte(payload))
			}
		}))
}

func testAzureTokenBackend(payload string) *httptest.Server {
	path := "/common/oauth2/token"

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != path && r.Method != "POST" {
				w.WriteHeader(404)
			} else if r.Method == "POST" && r.Body != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(200)
				w.Write([]byte(payload))
			} else if r.Header.Get("Authorization") != "Bearer imaginary_access_token" {
				w.WriteHeader(403)
			}
		}))
}

func TestAzureProviderGetEmailAddress(t *testing.T) {
	b := testAzureBackend(`{ "mail": "user@windows.net" }`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testAzureProvider(bURL.Host)

	session := &sessions.SessionState{AccessToken: "imaginary_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "user@windows.net", email)
}

func TestAzureProviderGetEmailAddressMailNull(t *testing.T) {
	b := testAzureBackend(`{ "mail": null, "otherMails": ["user@windows.net", "altuser@windows.net"] }`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testAzureProvider(bURL.Host)

	session := &sessions.SessionState{AccessToken: "imaginary_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "user@windows.net", email)
}

func TestAzureProviderGetEmailAddressGetUserPrincipalName(t *testing.T) {
	b := testAzureBackend(`{ "mail": null, "otherMails": [], "userPrincipalName": "user@windows.net" }`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testAzureProvider(bURL.Host)

	session := &sessions.SessionState{AccessToken: "imaginary_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "user@windows.net", email)
}

func TestAzureProviderGetEmailAddressFailToGetEmailAddress(t *testing.T) {
	b := testAzureBackend(`{ "mail": null, "otherMails": [], "userPrincipalName": null }`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testAzureProvider(bURL.Host)

	session := &sessions.SessionState{AccessToken: "imaginary_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, "type assertion to string failed", err.Error())
	assert.Equal(t, "", email)
}

func TestAzureProviderGetEmailAddressEmptyUserPrincipalName(t *testing.T) {
	b := testAzureBackend(`{ "mail": null, "otherMails": [], "userPrincipalName": "" }`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testAzureProvider(bURL.Host)

	session := &sessions.SessionState{AccessToken: "imaginary_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "", email)
}

func TestAzureProviderGetEmailAddressIncorrectOtherMails(t *testing.T) {
	b := testAzureBackend(`{ "mail": null, "otherMails": "", "userPrincipalName": null }`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testAzureProvider(bURL.Host)

	session := &sessions.SessionState{AccessToken: "imaginary_access_token"}
	email, err := p.GetEmailAddress(session)
	assert.Equal(t, "type assertion to string failed", err.Error())
	assert.Equal(t, "", email)
}

func TestAzureProviderGetsTokensInRedeem(t *testing.T) {
	body := fmt.Sprintf(`{ "access_token": "%s", "refresh_token": "%s", "id_token": "%s" }`, exampleAccessToken, exampleRefreshToken, exampleIDToken)
	b := testAzureTokenBackend(body)
	defer b.Close()
	timestamp, _ := time.Parse(time.RFC3339, "2019-10-18T11:55:49Z")
	bURL, _ := url.Parse(b.URL)
	p := testAzureProvider(bURL.Host)
	session, err := p.Redeem("http://redirect/", "code1234")
	assert.Equal(t, nil, err)
	assert.NotEqual(t, session, nil)
	assert.Equal(t, exampleAccessToken, session.AccessToken)
	assert.Equal(t, exampleRefreshToken, session.RefreshToken)
	assert.Equal(t, exampleIDToken, session.IDToken)
	assert.Equal(t, timestamp, session.ExpiresOn.UTC())
}

func TestAzureProviderNotRefreshWhenNotExpired(t *testing.T) {
	p := testAzureProvider("")

	session := &sessions.SessionState{AccessToken: "some_access_token", RefreshToken: "some_refresh_token", IDToken: "some_id_token", ExpiresOn: time.Now().Add(time.Duration(1) * time.Hour)}
	refreshNeeded, err := p.RefreshSessionIfNeeded(session)
	assert.Equal(t, nil, err)
	assert.False(t, refreshNeeded)
}

func TestAzureProviderRefreshWhenExpired(t *testing.T) {
	body := fmt.Sprintf(`{ "access_token": "%s", "refresh_token": "%s", "id_token": "%s" }`, exampleAccessToken, exampleRefreshToken, exampleIDToken)
	b := testAzureTokenBackend(body)
	defer b.Close()
	timestamp, _ := time.Parse(time.RFC3339, "2019-10-18T11:55:49Z")
	bURL, _ := url.Parse(b.URL)
	p := testAzureProvider(bURL.Host)

	session := &sessions.SessionState{AccessToken: "some_access_token", RefreshToken: "some_refresh_token", IDToken: "some_id_token"}
	_, err := p.RefreshSessionIfNeeded(session)
	assert.Equal(t, nil, err)
	assert.NotEqual(t, session, nil)
	assert.Equal(t, exampleAccessToken, session.AccessToken)
	assert.Equal(t, exampleRefreshToken, session.RefreshToken)
	assert.Equal(t, exampleIDToken, session.IDToken)
	assert.Equal(t, timestamp, session.ExpiresOn.UTC())
}
