package providers

import (
	"log"
	"net/http"
	"net/url"

	"github.com/bitly/go-simplejson"
	"github.com/bitly/google_auth_proxy/api"
)

type MyUsaProvider struct {
	*ProviderData
}

func NewMyUsaProvider(p *ProviderData) *MyUsaProvider {
	const myUsaHost string = "alpha.my.usa.gov"

	p.ProviderName = "MyUSA"
	if p.LoginUrl.String() == "" {
		p.LoginUrl = &url.URL{Scheme: "https",
			Host: myUsaHost,
			Path: "/oauth/authorize"}
	}
	if p.RedeemUrl.String() == "" {
		p.RedeemUrl = &url.URL{Scheme: "https",
			Host: myUsaHost,
			Path: "/oauth/token"}
	}
	if p.ProfileUrl.String() == "" {
		p.ProfileUrl = &url.URL{Scheme: "https",
			Host: myUsaHost,
			Path: "/api/v1/profile"}
	}
	if p.Scope == "" {
		p.Scope = "profile.email"
	}
	return &MyUsaProvider{ProviderData: p}
}

func (p *MyUsaProvider) GetEmailAddress(auth_response *simplejson.Json,
	access_token string) (string, error) {
	req, err := http.NewRequest("GET",
		p.ProfileUrl.String()+"?access_token="+access_token, nil)
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
