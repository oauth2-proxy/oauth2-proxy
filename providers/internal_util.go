package providers

import (
	"github.com/bitly/google_auth_proxy/api"
	"log"
	"net/http"
)

func validateToken(p Provider, access_token string,
	header http.Header) bool {
	if access_token == "" || p.Data().ValidateUrl == nil {
		return false
	}
	url := p.Data().ValidateUrl.String()
	if len(header) == 0 {
		url = url + "?access_token=" + access_token
	}
	if resp, err := api.RequestUnparsedResponse(url, header); err != nil {
		log.Printf("token validation request failed: %s", err)
		return false
	} else {
		return resp.StatusCode == 200
	}
}
