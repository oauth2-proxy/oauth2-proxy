package providers

import (
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/pusher/oauth2_proxy/pkg/logger"
	"github.com/pusher/oauth2_proxy/pkg/requests"
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
		logger.Printf("error attempting to strip %s: %s", param, err)
		return endpoint
	}

	if u.RawQuery != "" {
		values, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			logger.Printf("error attempting to strip %s: %s", param, err)
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
func validateToken(p Provider, accessToken string, header http.Header) bool {
	if accessToken == "" || p.Data().ValidateURL == nil || p.Data().ValidateURL.String() == "" {
		return false
	}
	endpoint := p.Data().ValidateURL.String()
	if len(header) == 0 {
		params := url.Values{"access_token": {accessToken}}
		endpoint = endpoint + "?" + params.Encode()
	}
	resp, err := requests.RequestUnparsedResponse(endpoint, header)
	if err != nil {
		logger.Printf("GET %s", stripToken(endpoint))
		logger.Printf("token validation request failed: %s", err)
		return false
	}

	body, _ := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	logger.Printf("%d GET %s %s", resp.StatusCode, stripToken(endpoint), body)

	if resp.StatusCode == 200 {
		return true
	}
	logger.Printf("token validation request failed: status %d - %s", resp.StatusCode, body)
	return false
}
