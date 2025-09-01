package encryption

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode"

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
	// We don't validate legacy SHA1 signatures anymore
	assert.False(t, checkSignature(sha1sig, seed, key, value, epoch))

	assert.False(t, checkSignature(sha256sig, seed, key, "tampered", epoch))
	assert.False(t, checkSignature(sha1sig, seed, key, "tampered", epoch))
}

func TestValidate(t *testing.T) {
	seed := "0123456789abcdef"
	key := "cookie-name"
	value := base64.URLEncoding.EncodeToString([]byte("I am soooo encoded"))
	epoch := int64(123456789)
	epochStr := strconv.FormatInt(epoch, 10)

	sha256sig, err := cookieSignature(sha256.New, seed, key, value, epochStr)
	assert.NoError(t, err)

	cookie := &http.Cookie{
		Name:  key,
		Value: value + "|" + epochStr + "|" + sha256sig,
	}

	validValue, timestamp, ok := Validate(cookie, seed, 0)
	assert.True(t, ok)
	assert.Equal(t, timestamp, time.Unix(epoch, 0))

	expectedValue, err := base64.URLEncoding.DecodeString(value)
	assert.NoError(t, err)
	assert.Equal(t, validValue, expectedValue)
}

func TestGenerateCodeVerifierString(t *testing.T) {
	randomString, err := GenerateCodeVerifierString(96)
	assert.NoError(t, err)

	// Should be 128 characters long
	assert.Equal(t, 128, len([]byte(randomString)))

	// All non-ascii characters removed should still be the original string
	removedChars := strings.Map(func(r rune) rune {
		if r > unicode.MaxASCII {
			return -1
		}
		return r
	}, randomString)
	assert.Equal(t, removedChars, randomString)
}
