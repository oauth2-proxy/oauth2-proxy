package providers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
)

func (p *ProviderData) Redeem(redirectUrl, code string) (body []byte, token string, err error) {
	if code == "" {
		err = errors.New("missing code")
		return
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectUrl)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	req, err := http.NewRequest("POST", p.RedeemUrl.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", err
	}
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, "", err
	}

	if resp.StatusCode != 200 {
		return body, "", fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemUrl.String(), body)
	}

	// blindly try json and x-www-form-urlencoded
	var jsonResponse struct {
		AccessToken string `json:"access_token"`
	}
	err = json.Unmarshal(body, &jsonResponse)
	if err == nil {
		return body, jsonResponse.AccessToken, nil
	}

	v, err := url.ParseQuery(string(body))
	return body, v.Get("access_token"), err
}

// GetLoginURL with typical oauth parameters
func (p *ProviderData) GetLoginURL(redirectURI, finalRedirect string) string {
	var a url.URL
	a = *p.LoginUrl
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("redirect_uri", redirectURI)
	params.Set("approval_prompt", "force")
	params.Add("scope", p.Scope)
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "code")
	if strings.HasPrefix(finalRedirect, "/") {
		params.Add("state", finalRedirect)
	}
	a.RawQuery = params.Encode()
	return a.String()
}
