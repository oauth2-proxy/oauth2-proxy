package providers

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

var authorizedAccessToken = "imaginary_access_token"

func CreateAuthorizedSession() *sessions.SessionState {
	return &sessions.SessionState{AccessToken: authorizedAccessToken}
}

func IsAuthorizedInHeader(reqHeader http.Header) bool {
	return IsAuthorizedInHeaderWithToken(reqHeader, authorizedAccessToken)
}

func IsAuthorizedInHeaderWithToken(reqHeader http.Header, token string) bool {
	return reqHeader.Get("Authorization") == fmt.Sprintf("Bearer %s", token)
}

func IsAuthorizedInURL(reqURL *url.URL) bool {
	return reqURL.Query().Get("access_token") == authorizedAccessToken
}

func isAuthorizedRefreshInURLWithToken(reqURL *url.URL, token string) bool {
	if token == "" {
		return false
	}
	return reqURL.Query().Get("refresh_token") == token
}
