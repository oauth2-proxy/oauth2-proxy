package main

import (
	"crypto/aes"
	"github.com/bmizerany/assert"
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
