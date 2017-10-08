package providers

import (
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"github.com/bitly/oauth2_proxy/api"
)

// stripToken is a helper function to obfuscate "access_token"
// query parameters
func stripToken(endpoint string) string {
	return stripParam("access_token", endpoint)
}

// stripParam generalizes the obfuscation of a particular
// query parameter - typically 'access_token' or 'client_secret'
// The parameter's second half is replaced by '...' and returned
// as part of the encoded query parameters.
// If the target parameter isn't found, the endpoint is returned
// unmodified.
func stripParam(param, endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		log.Printf("error attempting to strip %s: %s", param, err)
		return endpoint
	}

	if u.RawQuery != "" {
		values, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			log.Printf("error attempting to strip %s: %s", param, err)
			return u.String()
		}

		if val := values.Get(param); val != "" {
			values.Set(param, val[:(len(val)/2)]+"...")
			u.RawQuery = values.Encode()
			return u.String()
		}
	}

	return endpoint
}

// validateToken returns true if token is valid
func validateToken(p Provider, access_token string, header http.Header) bool {
	if access_token == "" || p.Data().ValidateURL == nil {
		return false
	}
	endpoint := p.Data().ValidateURL.String()
	if len(header) == 0 {
		params := url.Values{"access_token": {access_token}}
		endpoint = endpoint + "?" + params.Encode()
	}
	resp, err := api.RequestUnparsedResponse(endpoint, header)
	if err != nil {
		log.Printf("GET %s", stripToken(endpoint))
		log.Printf("token validation request failed: %s", err)
		return false
	}

	body, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	log.Printf("%d GET %s %s", resp.StatusCode, stripToken(endpoint), body)

	if resp.StatusCode == 200 {
		return true
	}
	log.Printf("token validation request failed: status %d - %s", resp.StatusCode, body)
	return false
}

func updateURL(url *url.URL, hostname string) {
	url.Scheme = "http"
	url.Host = hostname
}
