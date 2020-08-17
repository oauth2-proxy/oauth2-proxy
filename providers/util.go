package providers

import (
	"fmt"
	"net/http"
)

const (
	tokenTypeBearer = "Bearer"
	tokenTypeToken  = "token"

	acceptHeader          = "Accept"
	acceptApplicationJSON = "application/json"
)

func makeAuthorizationHeader(prefix, token string, extraHeaders map[string]string) http.Header {
	header := make(http.Header)
	for key, value := range extraHeaders {
		header.Add(key, value)
	}
	header.Set("Authorization", fmt.Sprintf("%s %s", prefix, token))
	return header
}

func makeOIDCHeader(accessToken string) http.Header {
	// extra headers required by the IDP when making authenticated requests
	extraHeaders := map[string]string{
		acceptHeader: acceptApplicationJSON,
	}
	return makeAuthorizationHeader(tokenTypeBearer, accessToken, extraHeaders)
}
