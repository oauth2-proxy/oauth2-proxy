package providers

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/Jing-ze/oauth2-proxy/pkg/util"
	"github.com/alibaba/higress/plugins/wasm-go/pkg/wrapper"
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
		util.Logger.Errorf("error attempting to strip %s: %s", param, err)
		return endpoint
	}

	if u.RawQuery != "" {
		values, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			util.Logger.Errorf("error attempting to strip %s: %s", param, err)
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
func validateToken(ctx context.Context, p Provider, accessToken string, header http.Header, client wrapper.HttpClient, callback func(args ...interface{}), timeout uint32) (bool, bool) {
	if accessToken == "" || p.Data().ValidateURL == nil || p.Data().ValidateURL.String() == "" {
		return false, false
	}
	endpoint := p.Data().ValidateURL.String()
	if len(header) == 0 {
		params := url.Values{"access_token": {accessToken}}
		if hasQueryParams(endpoint) {
			endpoint = endpoint + "&" + params.Encode()
		} else {
			endpoint = endpoint + "?" + params.Encode()
		}
	}
	var headerArray [][2]string
	for key, values := range header {
		for _, value := range values {
			headerArray = append(headerArray, [2]string{key, value})
		}
	}

	client.Get(endpoint, headerArray, func(statusCode int, responseHeaders http.Header, responseBody []byte) {
		util.Logger.Debugf("%d GET %s %s", statusCode, stripToken(endpoint), responseBody)
		if statusCode == 200 {
			callback(true)
		} else {
			util.SendError(fmt.Sprintf("token validation request failed: status %d - %s", statusCode, responseBody), nil, http.StatusInternalServerError)
		}
	}, timeout)
	return true, true
}

// hasQueryParams check if URL has query parameters
func hasQueryParams(endpoint string) bool {
	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		return false
	}

	return len(endpointURL.RawQuery) != 0
}
