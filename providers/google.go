package providers

import (
	"encoding/base64"
	"net/url"
	"strings"

	"github.com/bitly/go-simplejson"
)

type GoogleProvider struct {
	*ProviderData
}

func NewGoogleProvider(p *ProviderData) *GoogleProvider {
	p.ProviderName = "Google"
	if p.LoginUrl.String() == "" {
		p.LoginUrl = &url.URL{Scheme: "https",
			Host: "accounts.google.com",
			Path: "/o/oauth2/auth"}
	}
	if p.RedeemUrl.String() == "" {
		p.RedeemUrl = &url.URL{Scheme: "https",
			Host: "accounts.google.com",
			Path: "/o/oauth2/token"}
	}
	if p.Scope == "" {
		p.Scope = "profile email"
	}
	return &GoogleProvider{ProviderData: p}
}

func (s *GoogleProvider) GetEmailAddress(auth_response *simplejson.Json,
	unused_access_token string) (string, error) {
	idToken, err := auth_response.Get("id_token").String()
	if err != nil {
		return "", err
	}
	// id_token is a base64 encode ID token payload
	// https://developers.google.com/accounts/docs/OAuth2Login#obtainuserinfo
	jwt := strings.Split(idToken, ".")
	b, err := jwtDecodeSegment(jwt[1])
	if err != nil {
		return "", err
	}
	data, err := simplejson.NewJson(b)
	if err != nil {
		return "", err
	}
	email, err := data.Get("email").String()
	if err != nil {
		return "", err
	}
	return email, nil
}

func jwtDecodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}
