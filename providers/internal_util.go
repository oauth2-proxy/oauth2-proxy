package providers

import (
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"github.com/bitly/oauth2_proxy/api"
)

func validateToken(p Provider, access_token string, header http.Header) bool {
	if access_token == "" || p.Data().ValidateUrl == nil {
		return false
	}
	endpoint := p.Data().ValidateUrl.String()
	if len(header) == 0 {
		params := url.Values{"access_token": {access_token}}
		endpoint = endpoint + "?" + params.Encode()
	}
	resp, err := api.RequestUnparsedResponse(endpoint, header)
	if err != nil {
		log.Printf("token validation request failed: %s", err)
		return false
	}

	body, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode == 200 {
		return true
	}
	log.Printf("token validation request failed: status %d - %s", resp.StatusCode, body)
	return false
}
