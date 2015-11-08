package providers

import (
	"log"
	"net/http"
	"net/url"

	"github.com/bitly/oauth2_proxy/api"
)

type MyUsaProvider struct {
	*ProviderData
}

func NewMyUsaProvider(p *ProviderData) *MyUsaProvider {
	const myUsaHost string = "alpha.my.usa.gov"

	p.ProviderName = "MyUSA"
	if p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{Scheme: "https",
			Host: myUsaHost,
			Path: "/oauth/authorize"}
	}
	if p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{Scheme: "https",
			Host: myUsaHost,
			Path: "/oauth/token"}
	}
	if p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{Scheme: "https",
			Host: myUsaHost,
			Path: "/api/v1/profile"}
	}
	if p.ValidateURL.String() == "" {
		p.ValidateURL = &url.URL{Scheme: "https",
			Host: myUsaHost,
			Path: "/api/v1/tokeninfo"}
	}
	if p.Scope == "" {
		p.Scope = "profile.email"
	}
	return &MyUsaProvider{ProviderData: p}
}

func (p *MyUsaProvider) GetEmailAddress(s *SessionState) (string, error) {
	req, err := http.NewRequest("GET",
		p.ProfileURL.String()+"?access_token="+s.AccessToken, nil)
	if err != nil {
		log.Printf("failed building request %s", err)
		return "", err
	}
	json, err := api.Request(req)
	if err != nil {
		log.Printf("failed making request %s", err)
		return "", err
	}
	return json.Get("email").String()
}
