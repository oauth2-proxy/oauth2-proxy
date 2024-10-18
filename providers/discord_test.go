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

func testDiscordProvider(hostname string, guilds []string) *DiscordProvider {
	p := NewDiscordProvider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""},
		options.DiscordOptions{
			Guilds: guilds,
		})

	if hostname != "" {
		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		updateURL(p.Data().ProfileURL, hostname)
		originalGuildURL := discordGuildURL
		defer func() { discordGuildURL = originalGuildURL }()
		updateURL(discordGuildURL, hostname)
	}
	return p
}

func testDiscordBackend(payload string) *httptest.Server {
	guildsPath := "/api/users/@me/guilds"

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != guildsPath {
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
	g.Expect(providerData.ProfileURL.String()).To(Equal("https://discord.com/api/users/@me"))
	g.Expect(providerData.ValidateURL.String()).To(Equal("https://discord.com/api/users/@me"))
	g.Expect(providerData.Scope).To(Equal("identify email guilds"))
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

func TestDiscordProviderGetGuilds(t *testing.T) {
	b := testDiscordBackend(`[{"id":"1234","name":"testname"}]`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testDiscordProvider(bURL.Host, []string{})

	session := CreateAuthorizedSession()
	guilds, err := p.getUserGuilds(context.Background(), session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "1234", guilds[0].ID)
}

func TestDiscordProviderGetGuildsFailedRequest(t *testing.T) {
	b := testDiscordBackend("unused payload")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testDiscordProvider(bURL.Host, []string{})

	// We'll trigger a request failure by using an unexpected access
	// token. Alternatively, we could allow the parsing of the payload as
	// JSON to fail.
	session := &sessions.SessionState{AccessToken: "unexpected_access_token"}
	guilds, err := p.getUserGuilds(context.Background(), session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", guilds)
}

func TestDiscordProviderGuildsNotPresentInPayload(t *testing.T) {
	b := testDiscordBackend("{\"foo\": \"bar\"}")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testDiscordProvider(bURL.Host, []string{})

	session := CreateAuthorizedSession()
	guilds, err := p.getUserGuilds(context.Background(), session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", guilds)
}
