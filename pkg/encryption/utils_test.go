package encryption

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSecretBytesEncoded(t *testing.T) {
	for _, secretSize := range []int{16, 24, 32} {
		t.Run(fmt.Sprintf("%d", secretSize), func(t *testing.T) {
			secret := make([]byte, secretSize)
			_, err := io.ReadFull(rand.Reader, secret)
			assert.Equal(t, nil, err)

			// We test both padded & raw Base64 to ensure we handle both
			// potential user input routes for Base64
			base64Padded := base64.URLEncoding.EncodeToString(secret)
			sb := SecretBytes(base64Padded)
			assert.Equal(t, secret, sb)
			assert.Equal(t, len(sb), secretSize)

			base64Raw := base64.RawURLEncoding.EncodeToString(secret)
			sb = SecretBytes(base64Raw)
			assert.Equal(t, secret, sb)
			assert.Equal(t, len(sb), secretSize)
		})
	}
}

// A string that isn't intended as Base64 and still decodes (but to unintended length)
// will return the original secret as bytes
func TestSecretBytesEncodedWrongSize(t *testing.T) {
	for _, secretSize := range []int{15, 20, 28, 33, 44} {
		t.Run(fmt.Sprintf("%d", secretSize), func(t *testing.T) {
			secret := make([]byte, secretSize)
			_, err := io.ReadFull(rand.Reader, secret)
			assert.Equal(t, nil, err)

			// We test both padded & raw Base64 to ensure we handle both
			// potential user input routes for Base64
			base64Padded := base64.URLEncoding.EncodeToString(secret)
			sb := SecretBytes(base64Padded)
			assert.NotEqual(t, secret, sb)
			assert.NotEqual(t, len(sb), secretSize)
			// The given secret is returned as []byte
			assert.Equal(t, base64Padded, string(sb))

			base64Raw := base64.RawURLEncoding.EncodeToString(secret)
			sb = SecretBytes(base64Raw)
			assert.NotEqual(t, secret, sb)
			assert.NotEqual(t, len(sb), secretSize)
			// The given secret is returned as []byte
			assert.Equal(t, base64Raw, string(sb))
		})
	}
}

func TestSecretBytesNonBase64(t *testing.T) {
	trailer := "equals=========="
	assert.Equal(t, trailer, string(SecretBytes(trailer)))

	raw16 := "asdflkjhqwer)(*&"
	sb16 := SecretBytes(raw16)
	assert.Equal(t, raw16, string(sb16))
	assert.Equal(t, 16, len(sb16))

	raw24 := "asdflkjhqwer)(*&CJEN#$%^"
	sb24 := SecretBytes(raw24)
	assert.Equal(t, raw24, string(sb24))
	assert.Equal(t, 24, len(sb24))

	raw32 := "asdflkjhqwer)(*&1234lkjhqwer)(*&"
	sb32 := SecretBytes(raw32)
	assert.Equal(t, raw32, string(sb32))
	assert.Equal(t, 32, len(sb32))
}

func TestSignAndValidate(t *testing.T) {
	seed := "0123456789abcdef"
	key := "cookie-name"
	value := base64.URLEncoding.EncodeToString([]byte("I am soooo encoded"))
	epoch := "123456789"

	sha256sig, err := cookieSignature(sha256.New, seed, key, value, epoch)
	assert.NoError(t, err)
	sha1sig, err := cookieSignature(sha1.New, seed, key, value, epoch)
	assert.NoError(t, err)

	assert.True(t, checkSignature(sha256sig, seed, key, value, epoch))
	// This should be switched to False after fully deprecating SHA1
	assert.True(t, checkSignature(sha1sig, seed, key, value, epoch))

	assert.False(t, checkSignature(sha256sig, seed, key, "tampered", epoch))
	assert.False(t, checkSignature(sha1sig, seed, key, "tampered", epoch))
}
