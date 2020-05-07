package encryption

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLegacyEncodeAndDecodeAccessToken(t *testing.T) {
	const secret = "0123456789abcdefghijklmnopqrstuv"
	const token = "my access token"
	c, err := NewCipher([]byte(secret))
	assert.Equal(t, nil, err)

	//Legacy wrapped AES-CFB in Base64
	ciphertext, err := c.EncryptCFB([]byte(token))
	assert.Equal(t, nil, err)
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	decoded, err := c.LegacyDecrypt(encoded)
	assert.Equal(t, nil, err)

	assert.NotEqual(t, token, encoded)
	assert.Equal(t, token, decoded)
}

func TestLegacyEncodeAndDecodeAccessTokenB64(t *testing.T) {
	const secretBase64 = "A3Xbr6fu6Al0HkgrP1ztjb-mYiwmxgNPP-XbNsz1WBk="
	const token = "my access token"

	secret, err := base64.URLEncoding.DecodeString(secretBase64)
	assert.Equal(t, nil, err)
	c, err := NewCipher([]byte(secret))
	assert.Equal(t, nil, err)

	ciphertext, err := c.EncryptCFB([]byte(token))
	assert.Equal(t, nil, err)
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	decoded, err := c.LegacyDecrypt(encoded)
	assert.Equal(t, nil, err)

	assert.NotEqual(t, token, encoded)
	assert.Equal(t, token, decoded)
}

func TestEncryptAndDecryptCFB(t *testing.T) {
	var err error

	secret16 := make([]byte, 16)
	_, err = io.ReadFull(rand.Reader, secret16)
	assert.Equal(t, nil, err)

	c16, err := NewCipher([]byte(secret16))
	assert.Equal(t, nil, err)

	// Test random odd sizes of data
	for size := 93; size < 1000; size += 77 {
		data := make([]byte, size)
		_, err := io.ReadFull(rand.Reader, data)
		assert.Equal(t, nil, err)

		ciphertext, err := c16.EncryptCFB(data)
		assert.Equal(t, nil, err)

		newData, err := c16.DecryptCFB(ciphertext)
		assert.Equal(t, nil, err)
		assert.Equal(t, data, newData)
	}

	secret24 := make([]byte, 24)
	_, err = io.ReadFull(rand.Reader, secret24)
	assert.Equal(t, nil, err)

	c24, err := NewCipher([]byte(secret24))
	assert.Equal(t, nil, err)

	// Test random odd sizes of data
	for size := 89; size < 1000; size += 83 {
		data := make([]byte, size)
		_, err := io.ReadFull(rand.Reader, data)
		assert.Equal(t, nil, err)

		ciphertext, err := c24.EncryptCFB(data)
		assert.Equal(t, nil, err)

		newData, err := c24.DecryptCFB(ciphertext)
		assert.Equal(t, nil, err)
		assert.Equal(t, data, newData)
	}

	secret32 := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, secret32)
	assert.Equal(t, nil, err)

	c32, err := NewCipher([]byte(secret24))
	assert.Equal(t, nil, err)

	// Test random odd sizes of data
	for size := 79; size < 1000; size += 87 {
		data := make([]byte, size)
		_, err := io.ReadFull(rand.Reader, data)
		assert.Equal(t, nil, err)

		ciphertext, err := c32.EncryptCFB(data)
		assert.Equal(t, nil, err)

		newData, err := c32.DecryptCFB(ciphertext)
		assert.Equal(t, nil, err)
		assert.Equal(t, data, newData)
	}
}

func TestDecryptCFBWrongSecret(t *testing.T) {
	var err error

	secret1 := []byte("0123456789abcdefghijklmnopqrstuv")
	secret2 := []byte("9876543210abcdefghijklmnopqrstuv")

	c1, err := NewCipher([]byte(secret1))
	assert.Equal(t, nil, err)

	c2, err := NewCipher([]byte(secret2))
	assert.Equal(t, nil, err)

	data := []byte("f3928pufm982374dj02y485dsl34890u2t9nd4028s94dm58y2394087dhmsyt29h8df")

	ciphertext, err := c1.EncryptCFB(data)
	assert.Equal(t, nil, err)

	wrongData, err := c2.DecryptCFB(ciphertext)
	assert.Equal(t, nil, err)
	assert.NotEqual(t, data, wrongData)
}

func TestEncryptAndDecryptGCM(t *testing.T) {
	var err error

	secret16 := make([]byte, 16)
	_, err = io.ReadFull(rand.Reader, secret16)
	assert.Equal(t, nil, err)

	c16, err := NewCipher([]byte(secret16))
	assert.Equal(t, nil, err)

	// Test random odd sizes of data
	for size := 93; size < 1000; size += 77 {
		data := make([]byte, size)
		_, err := io.ReadFull(rand.Reader, data)
		assert.Equal(t, nil, err)

		ciphertext, err := c16.EncryptGCM(data)
		assert.Equal(t, nil, err)

		newData, err := c16.DecryptGCM(ciphertext)
		assert.Equal(t, nil, err)
		assert.Equal(t, data, newData)
	}

	secret24 := make([]byte, 24)
	_, err = io.ReadFull(rand.Reader, secret24)
	assert.Equal(t, nil, err)

	c24, err := NewCipher([]byte(secret24))
	assert.Equal(t, nil, err)

	// Test random odd sizes of data
	for size := 89; size < 1000; size += 83 {
		data := make([]byte, size)
		_, err := io.ReadFull(rand.Reader, data)
		assert.Equal(t, nil, err)

		ciphertext, err := c24.EncryptGCM(data)
		assert.Equal(t, nil, err)

		newData, err := c24.DecryptGCM(ciphertext)
		assert.Equal(t, nil, err)
		assert.Equal(t, data, newData)
	}

	secret32 := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, secret32)
	assert.Equal(t, nil, err)

	c32, err := NewCipher([]byte(secret24))
	assert.Equal(t, nil, err)

	// Test random odd sizes of data
	for size := 79; size < 1000; size += 87 {
		data := make([]byte, size)
		_, err := io.ReadFull(rand.Reader, data)
		assert.Equal(t, nil, err)

		ciphertext, err := c32.EncryptGCM(data)
		assert.Equal(t, nil, err)

		newData, err := c32.DecryptGCM(ciphertext)
		assert.Equal(t, nil, err)
		assert.Equal(t, data, newData)
	}
}

func TestDecryptGCMWrongSecret(t *testing.T) {
	var err error

	secret1 := []byte("0123456789abcdefghijklmnopqrstuv")
	secret2 := []byte("9876543210abcdefghijklmnopqrstuv")

	c1, err := NewCipher([]byte(secret1))
	assert.Equal(t, nil, err)

	c2, err := NewCipher([]byte(secret2))
	assert.Equal(t, nil, err)

	data := []byte("f3928pufm982374dj02y485dsl34890u2t9nd4028s94dm58y2394087dhmsyt29h8df")

	ciphertext, err := c1.EncryptGCM(data)
	assert.Equal(t, nil, err)

	// GCM is authenticated - this should lead to message authentication failed
	_, err = c2.DecryptGCM(ciphertext)
	assert.Error(t, err)
}
