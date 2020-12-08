package providers

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

// The following is a valid JWT, it can be decoded, edited and re-encoded using https://jwt.io/
var authorizedAccessToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkhvbWVyIFNpbXBzb24iLCJlbWFpbCI6IkNodW5reUxvdmVyNTNAYW9sLmNvbSIsImlhdCI6MTUxNjIzOTAyMiwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbInRlc3QtcmVhbG1yb2xlMSIsInRlc3QtcmVhbG1yb2xlMiJdfSwicmVzb3VyY2VfYWNjZXNzIjp7ImNsaWVudCI6eyJyb2xlcyI6WyJ0ZXN0LWNsaWVudHJvbGUxIiwidGVzdC1jbGllbnRyb2xlMiJdfX19.DqKfcantBn7B8acd9rl0LK8FL3sVhUcrM_AHztWI2A0"

func CreateAuthorizedSession() *sessions.SessionState {
	return &sessions.SessionState{AccessToken: authorizedAccessToken}
}

func IsAuthorizedInHeader(reqHeader http.Header) bool {
	return reqHeader.Get("Authorization") == fmt.Sprintf("Bearer %s", authorizedAccessToken)
}

func IsAuthorizedInURL(reqURL *url.URL) bool {
	return reqURL.Query().Get("access_token") == authorizedAccessToken
}
