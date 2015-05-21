package providers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
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
	if p.ValidateUrl.String() == "" {
		p.ValidateUrl = &url.URL{Scheme: "https",
			Host: "www.googleapis.com",
			Path: "/oauth2/v1/tokeninfo"}
	}
	if p.Scope == "" {
		p.Scope = "profile email"
	}
	return &GoogleProvider{ProviderData: p}
}

func (s *GoogleProvider) GetEmailAddress(body []byte, access_token string) (string, error) {
	var response struct {
		IdToken string `json:"id_token"`
	}

	if err := json.Unmarshal(body, &response); err != nil {
		return "", err
	}

	// id_token is a base64 encode ID token payload
	// https://developers.google.com/accounts/docs/OAuth2Login#obtainuserinfo
	jwt := strings.Split(response.IdToken, ".")
	b, err := jwtDecodeSegment(jwt[1])
	if err != nil {
		return "", err
	}

	var email struct {
		Email string `json:"email"`
	}
	err = json.Unmarshal(b, &email)
	if err != nil {
		return "", err
	}
	if email.Email == "" {
		return "", errors.New("missing email")
	}
	return email.Email, nil
}

func jwtDecodeSegment(seg string) ([]byte, error) {
	if l := len(seg) % 4; l > 0 {
		seg += strings.Repeat("=", 4-l)
	}

	return base64.URLEncoding.DecodeString(seg)
}

func (p *GoogleProvider) ValidateToken(access_token string) bool {
	return validateToken(p, access_token, nil)
}
