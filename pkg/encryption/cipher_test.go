package encryption

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSignAndValidate(t *testing.T) {
	seed := []byte("0123456789abcdef")
	key := "cookie-name"
	value := base64.URLEncoding.EncodeToString([]byte("I am soooo encoded"))
	epoch := "123456789"

	sha256sig := hmacToSignature(cookieHMAC(sha256.New, seed, key, value, epoch))
	sha1sig := hmacToSignature(cookieHMAC(sha1.New, seed, key, value, epoch))

	assert.True(t, checkSignature(sha256sig, seed, key, value, epoch))
	// This should be switched to False after fully deprecating SHA1
	assert.True(t, checkSignature(sha1sig, seed, key, value, epoch))

	assert.False(t, checkSignature(sha256sig, seed, key, "tampered", epoch))
	assert.False(t, checkSignature(sha1sig, seed, key, "tampered", epoch))
}

func TestEncodeAndDecodeAccessToken(t *testing.T) {
	const secret = "0123456789abcdefghijklmnopqrstuv"
	const token = "my access token"
	c, err := NewCipher([]byte(secret))
	assert.Equal(t, nil, err)

	encoded, err := c.Encrypt(token)
	assert.Equal(t, nil, err)

	decoded, err := c.Decrypt(encoded)
	assert.Equal(t, nil, err)

	assert.NotEqual(t, token, encoded)
	assert.Equal(t, token, decoded)
}

func TestEncodeAndDecodeAccessTokenB64(t *testing.T) {
	const secretBase64 = "A3Xbr6fu6Al0HkgrP1ztjb-mYiwmxgNPP-XbNsz1WBk="
	const token = "my access token"

	secret, err := base64.URLEncoding.DecodeString(secretBase64)
	assert.Equal(t, nil, err)
	c, err := NewCipher([]byte(secret))
	assert.Equal(t, nil, err)

	encoded, err := c.Encrypt(token)
	assert.Equal(t, nil, err)

	decoded, err := c.Decrypt(encoded)
	assert.Equal(t, nil, err)

	assert.NotEqual(t, token, encoded)
	assert.Equal(t, token, decoded)
}
