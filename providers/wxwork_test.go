package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/stretchr/testify/assert"
)

func testWxWorkProvider(hostname string) *WxWorkProvider {
	p := NewWxWorkProvider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""})
	if hostname != "" {
		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		updateURL(p.Data().ProfileURL, hostname)
	}
	return p
}

func TestNewWxWorkProvider(t *testing.T) {
	g := NewWithT(t)

	// Test that defaults are set when calling for a new provider with nothing set
	providerData := NewWxWorkProvider(&ProviderData{}).Data()
	g.Expect(providerData.ProviderName).To(Equal("WxWork"))
	g.Expect(providerData.LoginURL.String()).To(Equal("https://open.weixin.qq.com/connect/oauth2/authorize"))
	g.Expect(providerData.RedeemURL.String()).To(Equal("https://qyapi.weixin.qq.com/cgi-bin/auth/getuserinfo"))
	g.Expect(providerData.ProfileURL.String()).To(Equal("https://qyapi.weixin.qq.com/cgi-bin/auth/getuserdetail"))
	g.Expect(providerData.ValidateURL.String()).To(Equal("https://qyapi.weixin.qq.com/cgi-bin/auth/getuserdetail"))
	g.Expect(providerData.Scope).To(Equal("snsapi_privateinfo"))
}
