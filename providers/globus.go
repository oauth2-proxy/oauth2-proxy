package providers

import (
        "bytes"
        "encoding/json"
        "errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

type GlobusProvider struct {
	*ProviderData
}

type Token struct {
    AccessToken string  `json:"access_token"`
    ExpiresIn   int     `json:"expires_in"`
    Scope       string  `json:"scope"`
    Tokens      []Token `json:"other_tokens"`
}

//https://auth.globus.org/.well-known/openid-configuration
func NewGlobusProvider(p *ProviderData) *GlobusProvider {
	p.ProviderName = "Globus"
	if p.LoginURL == nil || p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{
			Scheme: "https",
			Host:   "auth.globus.org",
			Path:   "/v2/oauth2/authorize",
		}
	}
	if p.RedeemURL == nil || p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{
			Scheme: "https",
			Host:   "auth.globus.org",
			Path:   "/v2/oauth2/token",
		}
	}
	if p.ValidateURL == nil || p.ValidateURL.String() == "" {
		p.ValidateURL = &url.URL{
			Scheme: "https",
			Host:   "auth.globus.org",
			Path:   "/v2/oauth2/token/introspect",
		}
	}
	if p.ProfileURL == nil || p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{
			Scheme: "https",
			Host:   "auth.globus.org",
			Path:   "/v2/oauth2/userinfo",
		}
	}
	if p.Scope == "" {

		// TODO:  scopes should be configurable
		p.Scope = "openid email profile urn:globus:auth:scope:auth.globus.org:view_identities urn:globus:auth:scope:transfer.api.globus.org:all urn:globus:auth:scope:data.materialsdatafacility.org:all urn:globus:auth:scope:transfer.api.globus.org:all urn:globus:auth:scope:search.api.globus.org:search"

	}
	return &GlobusProvider{ProviderData: p}
}

func (p *GlobusProvider) GetEmailAddress(s *SessionState) (string, error) {
	var userinfo struct {
		Email             string `json:"email"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		Sub               string `json:"sub"`
	}

	req, _ := http.NewRequest("GET", p.ProfileURL.String(), nil)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.AccessToken))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return "", err
	}

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("got %d from %q %s",
			resp.StatusCode, p.ProfileURL.String(), body)
	} else {
		log.Printf("got %d from %q %s", resp.StatusCode, p.ProfileURL.String(), body)
	}

	if err := json.Unmarshal(body, &userinfo); err != nil {
		return "", fmt.Errorf("%s unmarshaling %s", err, body)
	}

	return userinfo.Email, nil
}

func (p *GlobusProvider) Redeem(redirectURL, code string) (s *SessionState, err error) {
	if code == "" {
		err = errors.New("missing code")
		return
	}

	params := url.Values{}
	params.Add("redirect_uri", redirectURL)
	params.Add("client_id", p.ClientID)
	params.Add("client_secret", p.ClientSecret)
	params.Add("code", code)
	params.Add("grant_type", "authorization_code")
	if p.ProtectedResource != nil && p.ProtectedResource.String() != "" {
		params.Add("resource", p.ProtectedResource.String())
	}

	var req *http.Request
	req, err = http.NewRequest("POST", p.RedeemURL.String(), bytes.NewBufferString(params.Encode()))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var resp *http.Response
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	var body []byte
	body, err = ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return
	}

	if resp.StatusCode != 200 {
		err = fmt.Errorf("got %d from %q %s", resp.StatusCode, p.RedeemURL.String(), body)
		return
	}
	globusTokens := Token{}

	err = json.Unmarshal(body, &globusTokens)
	if err == nil {


		otherTokens := ""
        	for _, token := range globusTokens.Tokens {
			otherTokens += " " + token.Scope + "=" + token.AccessToken
                }
		fmt.Printf("Found access tokens: %s\n", otherTokens)


                s = &SessionState{
                        AccessToken: globusTokens.AccessToken,
                        OtherTokens: otherTokens,
                }
		return
        }

	var v url.Values
	v, err = url.ParseQuery(string(body))
	if err != nil {
		return
	}
	if a := v.Get("access_token"); a != "" {
		fmt.Printf("using existing access token\n")
		s = &SessionState{AccessToken: a}
	} else {
		err = fmt.Errorf("no access token found %s", body)
	}
	return
}
