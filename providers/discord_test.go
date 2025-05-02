package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

func testDiscordProvider(t testing.TB, hostname string, restrictedUserIDs []string) *DiscordProvider {
	p := NewDiscordProvider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""},
		options.DiscordOptions{
			RestrictedUserIDs: restrictedUserIDs,
		})

	if hostname != "" {
		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		updateURL(p.Data().ProfileURL, hostname)
		originalProfileURL := discordDefaultProfileURL
		t.Cleanup(func() { discordDefaultProfileURL = originalProfileURL })
		updateURL(originalProfileURL, hostname)
	}
	return p
}

func testDiscordBackend(payload string) *httptest.Server {
	profilePath := discordDefaultProfileURL.Path

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != profilePath {
				w.WriteHeader(404)
			} else if !IsAuthorizedInHeader(r.Header) {
				w.WriteHeader(403)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			}
		}))
}

func TestNewDiscordProvider(t *testing.T) {
	g := NewWithT(t)

	// Test that defaults are set when calling for a new provider with nothing set
	providerData := NewDiscordProvider(&ProviderData{}, options.DiscordOptions{}).Data()
	g.Expect(providerData.ProviderName).To(Equal("Discord"))
	g.Expect(providerData.LoginURL.String()).To(Equal("https://discord.com/api/oauth2/authorize"))
	g.Expect(providerData.RedeemURL.String()).To(Equal("https://discord.com/api/oauth2/token"))
	g.Expect(providerData.ProfileURL.String()).To(Equal("https://discord.com/api/oauth2/@me"))
	g.Expect(providerData.ValidateURL.String()).To(Equal("https://discord.com/api/oauth2/@me"))
	g.Expect(providerData.Scope).To(Equal("identify"))
}

func TestDiscordProviderOverrides(t *testing.T) {
	p := NewDiscordProvider(
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
			Scope: "profile"},
		options.DiscordOptions{})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Discord", p.Data().ProviderName)
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

func TestDiscordProviderGetTokenInfo(t *testing.T) {
	b := testDiscordBackend(`{"user":{"id":"1234","username":"john"}}`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testDiscordProvider(t, bURL.Host, []string{})

	session := CreateAuthorizedSession()
	token, err := p.getTokenInfo(context.Background(), session)
	assert.NoError(t, err)
	assert.Equal(t, "1234", token.User.ID)
	assert.Equal(t, "john", token.User.Username)
}

func TestDiscordProviderEnrichSession(t *testing.T) {
	b := testDiscordBackend(`{"user":{"id":"1234","username":"john"}}`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testDiscordProvider(t, bURL.Host, []string{})

	session := CreateAuthorizedSession()
	assert.NoError(t, p.EnrichSession(context.Background(), session))
	assert.Equal(t, "1234", session.User)
	assert.Equal(t, "john", session.PreferredUsername)
}

func TestDiscordProviderValidateUserID(t *testing.T) {
	userID := "1234"
	b := testDiscordBackend(`{"user":{"id":"` + userID + `","username":"john"}}`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	for _, testCase := range []struct {
		Name              string
		RestrictedUserIDs []string
		ExpectedAccess    bool
	}{
		{
			Name:              "no restriction defined",
			RestrictedUserIDs: []string{},
			ExpectedAccess:    true,
		},
		{
			Name:              "user ID in restricted list",
			RestrictedUserIDs: []string{userID},
			ExpectedAccess:    true,
		},
		{
			Name:              "user ID not in restricted list",
			RestrictedUserIDs: []string{"not our user ID"},
			ExpectedAccess:    false,
		},
	} {
		t.Run(testCase.Name, func(t *testing.T) {
			p := testDiscordProvider(t, bURL.Host, testCase.RestrictedUserIDs)

			session := CreateAuthorizedSession()
			assert.NoError(t, p.EnrichSession(context.Background(), session))
			assert.Equal(t, testCase.ExpectedAccess, p.validateUserID(session))
		})
	}
}

func TestDiscordProviderTokenInfoFailedRequest(t *testing.T) {
	b := testDiscordBackend("unused payload")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testDiscordProvider(t, bURL.Host, []string{})

	// We'll trigger a request failure by using an unexpected access
	// token. Alternatively, we could allow the parsing of the payload as
	// JSON to fail.
	session := &sessions.SessionState{AccessToken: "unexpected_access_token"}
	token, err := p.getTokenInfo(context.Background(), session)
	assert.Error(t, err)
	assert.Nil(t, token)
}
