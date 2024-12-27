package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

const (
	picsSignOutAllDevicesPath = "/sign_out_all_sessions"
)

func PicsSignOutAllSessions(backendLogoutAllSessionsURL string, introspectClaims string, accessToken string) (resp *http.Response, err error) {
	userId, err := getUserId(introspectClaims)
	if err != nil {
		return nil, fmt.Errorf("error getting userId from instrospect claims: %v", err)
	}

	backendLogoutURL := strings.ReplaceAll(backendLogoutAllSessionsURL, "{user_id}", userId)

	dummyBody := strings.NewReader(`{}`)
	req, err := http.NewRequest("POST", backendLogoutURL, dummyBody)
	if err != nil {
		return nil, fmt.Errorf("error creating post request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("API-Version", "1")
	req.Header.Set("Accept", "application/json")

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error logging out from IAM: %v", err)
	}

	return resp, err
}

func getUserId(introspectClaims string) (string, error) {
	decodedClaims, err := base64.StdEncoding.DecodeString(introspectClaims)
	if err != nil {
		logger.Errorf("error decoding claims: %v", err)
		return "", err
	}

	var claims map[string]interface{}
	err = json.Unmarshal(decodedClaims, &claims)
	if err != nil {
		logger.Errorf("error unmarshalling claims: %v", err)
		return "", err
	}

	userId, ok := claims["sub"].(string)
	if !ok {
		logger.Errorf("error extracting 'sub' from claims")
		return "", err
	}

	return userId, nil
}
