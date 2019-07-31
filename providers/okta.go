package providers

import (
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/requests"
)

type OktaProvider struct {
	*ProviderData
}

func (p *OktaProvider) SetOktaDomain(domain string) {
	if p.LoginURL == nil || p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   domain,
			Path:   "/oauth2/v1/authorize",
		}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   domain,
			Path:   "/oauth2/v1/token",
		}
	}
	if p.ValidateURL == nil || p.ValidateURL.String() == "" {
		p.ValidateURL = &url.URL{
			Scheme: "https",
			Host:   domain,
			Path:   "/oauth2/v1/userinfo",
		}
	}
}

func NewOktaProvider(p *ProviderData) *OktaProvider {
	p.ProviderName = "Okta"
	if p.Scope == "" {
		p.Scope = "openid profile email"
	}
	return &OktaProvider{ProviderData: p}
}

func getOktaHeader(accessToken string) http.Header {
	header := make(http.Header)
	header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	return header
}

func (p *OktaProvider) GetEmailAddress(s *sessions.SessionState) (string, error) {

	req, err := http.NewRequest("GET",
		p.ValidateURL.String(), nil)
	if err != nil {
		log.Printf("failed building request %s", err)
		return "", err
	}
	req.Header = getOktaHeader(s.AccessToken)
	json, err := requests.Request(req)
	if err != nil {
		log.Printf("failed making request %s", err)
		return "", err
	}
	return json.Get("email").String()
}
