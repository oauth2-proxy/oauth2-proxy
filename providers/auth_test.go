package providers

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
)

var authorizedAccessToken = "imaginary_access_token"

func CreateAuthorizedSession() *sessions.SessionState {
	return &sessions.SessionState{AccessToken: authorizedAccessToken}
}

func IsAuthorizedInHeader(reqHeader http.Header) bool {
	return reqHeader.Get("Authorization") == fmt.Sprintf("Bearer %s", authorizedAccessToken)
}

func IsAuthorizedInURL(reqURL *url.URL) bool {
	return reqURL.Query().Get("access_token") == authorizedAccessToken
}
