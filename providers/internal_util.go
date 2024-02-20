package providers

import (
	"context"
	"net/http"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
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
		logger.Errorf("error attempting to strip %s: %s", param, err)
		return endpoint
	}

	if u.RawQuery != "" {
		values, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			logger.Errorf("error attempting to strip %s: %s", param, err)
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
func validateToken(ctx context.Context, p Provider, accessToken string, header http.Header) bool {
	if accessToken == "" || p.Data().ValidateURL == nil || p.Data().ValidateURL.String() == "" {
		return false
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

	result := requests.New(endpoint).
		WithContext(ctx).
		WithClient(p.Data().Client).
		WithHeaders(header).
		Do()
	if result.Error() != nil {
		logger.Errorf("GET %s", stripToken(endpoint))
		logger.Errorf("token validation request failed: %s", result.Error())
		return false
	}

	logger.Printf("%d GET %s %s", result.StatusCode(), stripToken(endpoint), result.Body())

	if result.StatusCode() == 200 {
		return true
	}
	logger.Errorf("token validation request failed: status %d - %s", result.StatusCode(), result.Body())
	return false
}

// hasQueryParams check if URL has query parameters
func hasQueryParams(endpoint string) bool {
	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		return false
	}

	return len(endpointURL.RawQuery) != 0
}
