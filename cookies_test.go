package main

import (
	"crypto/aes"
	"github.com/bmizerany/assert"
	"strings"
	"testing"
)

func TestEncodeAndDecodeAccessToken(t *testing.T) {
	const key = "0123456789abcdefghijklmnopqrstuv"
	const access_token = "my access token"
	c, err := aes.NewCipher([]byte(key))
	assert.Equal(t, nil, err)

	encoded_token, err := encodeAccessToken(c, access_token)
	assert.Equal(t, nil, err)

	decoded_token, err := decodeAccessToken(c, encoded_token)
	assert.Equal(t, nil, err)

	assert.NotEqual(t, access_token, encoded_token)
	assert.Equal(t, access_token, decoded_token)
}

func TestBuildCookieValueWithoutAccessToken(t *testing.T) {
	value, err := buildCookieValue("michael.bland@gsa.gov", nil, "")
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", value)
}

func TestBuildCookieValueWithAccessTokenAndNilCipher(t *testing.T) {
	value, err := buildCookieValue("michael.bland@gsa.gov", nil,
		"access token")
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", value)
}

func TestParseCookieValueWithoutAccessToken(t *testing.T) {
	email, user, access_token, err := parseCookieValue(
		"michael.bland@gsa.gov", nil)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
	assert.Equal(t, "michael.bland", user)
	assert.Equal(t, "", access_token)
}

func TestParseCookieValueWithAccessTokenAndNilCipher(t *testing.T) {
	email, user, access_token, err := parseCookieValue(
		"michael.bland@gsa.gov|access_token", nil)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
	assert.Equal(t, "michael.bland", user)
	assert.Equal(t, "", access_token)
}

func TestBuildAndParseCookieValueWithAccessToken(t *testing.T) {
	aes_cipher, err := aes.NewCipher([]byte("0123456789abcdef"))
	assert.Equal(t, nil, err)
	value, err := buildCookieValue("michael.bland@gsa.gov", aes_cipher,
		"access_token")
	assert.Equal(t, nil, err)

	prefix := "michael.bland@gsa.gov|"
	if !strings.HasPrefix(value, prefix) {
		t.Fatal("cookie value does not start with \"%s\": %s",
			prefix, value)
	}

	email, user, access_token, err := parseCookieValue(value, aes_cipher)
	assert.Equal(t, nil, err)
	assert.Equal(t, "michael.bland@gsa.gov", email)
	assert.Equal(t, "michael.bland", user)
	assert.Equal(t, "access_token", access_token)
}
