package providers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"golang.org/x/oauth2"
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

func makeLoginURL(p *ProviderData, redirectURI, state string, extraParams url.Values) url.URL {
	a := *p.LoginURL
	params, _ := url.ParseQuery(a.RawQuery)
	params.Set("redirect_uri", redirectURI)
	if p.AcrValues != "" {
		params.Add("acr_values", p.AcrValues)
	}
	if p.Prompt != "" {
		params.Set("prompt", p.Prompt)
	} else { // Legacy variant of the prompt param:
		params.Set("approval_prompt", p.ApprovalPrompt)
	}
	params.Add("scope", p.Scope)
	params.Set("client_id", p.ClientID)
	params.Set("response_type", "code")
	params.Add("state", state)
	for n, p := range extraParams {
		for _, v := range p {
			params.Add(n, v)
		}
	}
	a.RawQuery = params.Encode()
	return a
}

// getIDToken extracts an IDToken stored in the `Extra` fields of an
// oauth2.Token
func getIDToken(token *oauth2.Token) string {
	idToken, ok := token.Extra("id_token").(string)
	if !ok {
		return ""
	}
	return idToken
}

// formatGroup coerces an OIDC groups claim into a string
// If it is non-string, marshal it into JSON.
func formatGroup(rawGroup interface{}) (string, error) {
	if group, ok := rawGroup.(string); ok {
		return group, nil
	}

	jsonGroup, err := json.Marshal(rawGroup)
	if err != nil {
		return "", err
	}
	return string(jsonGroup), nil
}
