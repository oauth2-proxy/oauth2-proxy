package middleware

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// splitAuthHeader takes the auth header value and splits it into the token type
// and the token value.
func splitAuthHeader(header string) (string, string, error) {
	s := strings.Split(header, " ")
	if len(s) != 2 {
		return "", "", fmt.Errorf("invalid authorization header: %q", header)
	}
	return s[0], s[1], nil
}

// getBasicAuthCredentials decodes a basic auth token and extracts the user
// and password pair.
func getBasicAuthCredentials(token string) (string, string, error) {
	b, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", "", fmt.Errorf("invalid basic auth token: %v", err)
	}

	pair := strings.SplitN(string(b), ":", 2)
	if len(pair) != 2 {
		return "", "", fmt.Errorf("invalid format: %q", b)
	}
	// user, password
	return pair[0], pair[1], nil
}
