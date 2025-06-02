package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
)

const (
	picsSignOutAllSessionsPath = "/sign_out_all_sessions"
)

func PicsSignOutAllSessions(backendLogoutAllSessionsURL string, introspectClaims string, accessToken string) (resp requests.Result, err error) {
	userID, err := getUserID(introspectClaims)
	if err != nil {
		return nil, fmt.Errorf("error getting userID from instrospect claims: %v", err)
	}

	backendLogoutURL := strings.ReplaceAll(backendLogoutAllSessionsURL, "{user_id}", userID)
	resp = requests.New(backendLogoutURL).
		WithMethod("POST").
		SetHeader("Authorization", "Bearer "+accessToken).
		SetHeader("API-Version", "1").
		SetHeader("Accept", "application/json").
		Do()

	if resp.Error() != nil {
		return nil, fmt.Errorf("error logging out from IAM: %v", resp.Error())
	}

	return resp, err
}

func PicsRevokeAcessToken(backendRevokeURL string, accessToken string, clientID string, clientSecret string) (err error) {
	authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+clientSecret))
	body := "token=" + accessToken

	resp := requests.New(backendRevokeURL).
		WithMethod("POST").
		SetHeader("Authorization", authHeader).
		SetHeader("api-version", "2").
		SetHeader("Content-Type", "application/x-www-form-urlencoded").
		SetHeader("Accept", "application/json").
		WithBody(strings.NewReader(body)).
		Do()

	if resp.Error() != nil {
		return fmt.Errorf("error revoking access token: %v", resp.Error())
	}

	if resp.StatusCode() != 200 {
		return fmt.Errorf("error revoking access token: %v", resp.Error())
	}

	return nil
}

func getUserID(introspectClaims string) (string, error) {
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

	userID, ok := claims["sub"].(string)
	if !ok {
		logger.Errorf("error extracting 'sub' from claims")
		return "", err
	}

	return userID, nil
}
