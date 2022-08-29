package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

// func testTOTVSProvider(hostname string) *TOTVSProvider {
// 	p := NewTOTVSProvider(
// 		&ProviderData{
// 			ProviderName: "",
// 			LoginURL:     &url.URL{},
// 			RedeemURL:    &url.URL{},
// 			ProfileURL:   &url.URL{},
// 			ValidateURL:  &url.URL{},
// 			Scope:        "",
// 			EmailClaim:   "email"})
// 	if hostname != "" {
// 		updateURL(p.Data().LoginURL, hostname)
// 		updateURL(p.Data().RedeemURL, hostname)
// 		updateURL(p.Data().ProfileURL, hostname)
// 	}
// 	return p
// }

func newTOTVSProvider(t *testing.T) *TOTVSProvider {
	p := NewTOTVSProvider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        "",
			EmailClaim:   "email"})
	return p
}

func TestNewTOTVSProvider(t *testing.T) {
	g := NewWithT(t)

	// Test that defaults are set when calling for a new provider with nothing set
	providerData := NewTOTVSProvider(&ProviderData{}).Data()
	g.Expect(providerData.ProviderName).To(Equal("TOTVS"))
	g.Expect(providerData.LoginURL.String()).To(Equal("https://app.fluigidentity.com/accounts/oauth/authorize"))
	g.Expect(providerData.RedeemURL.String()).To(Equal("https://api-fluig.totvs.app/accounts/oauth/token"))
	g.Expect(providerData.ProfileURL.String()).To(Equal("https://api-fluig.totvs.app/manager/api/v1/me"))
	g.Expect(providerData.ValidateURL.String()).To(Equal("https://api-fluig.totvs.app/manager/api/v1/me"))
	g.Expect(providerData.Scope).To(Equal("email"))
}

func TestTOTVSProviderOverrides(t *testing.T) {
	p := NewTOTVSProvider(
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
			Scope: "email"})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "TOTVS", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/oauth/auth",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://example.com/oauth/profile",
		p.Data().ProfileURL.String())
	assert.Equal(t, "https://example.com/oauth/tokeninfo",
		p.Data().ValidateURL.String())
	assert.Equal(t, "email", p.Data().Scope)
}

func TestTOTVSProviderGetLoginURL(t *testing.T) {
	p := newTOTVSProvider(t)

	result := p.GetLoginURL("http://redirect/", "state", "", url.Values{})
	assert.Contains(t, result, "redirect_uri="+url.QueryEscape("http://redirect/"))
	assert.Contains(t, result, "client_id="+p.ClientID)
	assert.Contains(t, result, "response_type=code")
	assert.Contains(t, result, "state=state")
	assert.Contains(t, result, "grant_type=authorization_code")
}

func TestTOTVSProviderAuthorize(t *testing.T) {
	p := newTOTVSProvider(t)

	_, err := p.Authorize(context.Background(), &sessions.SessionState{})

	assert.NoError(t, err)
}

type TOTVSClaims struct {
	TenantIdpID     string   `json:"tenantIdpId"`
	LastUpdateDate  int64    `json:"lastUpdateDate"`
	UserName        string   `json:"user_name"`
	Roles           []string `json:"roles,omitempty"`
	IdmRefreshToken string   `json:"idmRefreshToken"`
	FullName        string   `json:"fullName"`
	TenantCode      string   `json:"tenantCode"`
	PartnerCompany  bool     `json:"partnerCompany"`
	IdmAccessToken  string   `json:"idmAccessToken"`
	Authorities     []string `json:"authorities"`
	ClientID        string   `json:"client_id"`
	UserTimeZone    string   `json:"userTimeZone"`
	CompanyID       string   `json:"companyId"`
	Domain          string   `json:"domain"`
	Scope           []string `json:"scope,omitempty"`
	UserIdpID       string   `json:"userIdpId"`
	Email           string   `json:"email"`
	Apps            []string `json:"apps"`
	jwt.StandardClaims
}

func getClaims() TOTVSClaims {
	claims := TOTVSClaims{
		"f4b5deaf112f4f2eaeabfbe5e8558f1b",
		int64(60),
		"felipe.conti@totvs.com.br",
		[]string{""},
		"976c124502664a6b84f1d77c28e71536",
		"Felipe Bonvicini Conti",
		"totvsapps",
		false,
		"f6a2fd0b7b044942924562ab5c0bc083",
		[]string{"admin", "user"},
		"totvsappstest",
		"America/Sao_Paulo",
		"f4b5deaf112f4f2eaeabfbe5e8558f1b",
		"totvsapps",
		[]string{""},
		"ax4ehrs3qxtgp17d",
		"felipe.conti@totvs.com.br",
		[]string{"accounts", "standard", "tasks", "manager"},
		jwt.StandardClaims{
			Audience:  "fluig_authenticator_resource",
			ExpiresAt: time.Now().Unix() + int64(60),
			Id:        "foo",
			IssuedAt:  time.Now().Unix(),
			Issuer:    "*.fluig.io",
			NotBefore: time.Now().Unix() - 1,
			Subject:   "felipe.conti@totvs.com.br",
		},
	}
	return claims
}

func TestTOTVSProviderGetEmailAddress(t *testing.T) {
	p := newTOTVSProvider(t)

	type redeemResponse struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}

	claims, err := json.Marshal(getClaims())
	assert.Equal(t, nil, err)

	body, err := json.Marshal(redeemResponse{
		AccessToken:  "ignored prefix." + base64.URLEncoding.EncodeToString(claims),
		ExpiresIn:    10,
		RefreshToken: "refresh12345",
	})
	assert.Equal(t, nil, err)

	redeemServer := func(body []byte) (*url.URL, *httptest.Server) {
		s := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			rw.Write(body)
		}))
		u, _ := url.Parse(s.URL)
		return u, s
	}

	var server *httptest.Server
	p.RedeemURL, server = redeemServer(body)
	defer server.Close()

	session, err := p.Redeem(context.Background(), "http://redirect/", "code1234", "123")
	assert.Equal(t, nil, err)
	assert.NotEqual(t, session, nil)
	assert.Equal(t, "felipe.conti@totvs.com.br", session.Email)
	assert.Equal(t, "refresh12345", session.RefreshToken)
}
