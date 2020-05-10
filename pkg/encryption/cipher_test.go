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

	sha256sig := cookieSignature(sha256.New, seed, key, value, epoch)
	sha1sig := cookieSignature(sha1.New, seed, key, value, epoch)

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

	encoded, err := c.Encrypt([]byte(token))
	assert.Equal(t, nil, err)

	decoded, err := c.Decrypt(encoded)
	assert.Equal(t, nil, err)

	assert.NotEqual(t, []byte(token), encoded)
	assert.Equal(t, []byte(token), decoded)
}

func TestEncodeAndDecodeAccessTokenB64(t *testing.T) {
	const secretBase64 = "A3Xbr6fu6Al0HkgrP1ztjb-mYiwmxgNPP-XbNsz1WBk="
	const token = "my access token"

	secret, err := base64.URLEncoding.DecodeString(secretBase64)
	assert.Equal(t, nil, err)
	c, err := NewCipher([]byte(secret))
	assert.Equal(t, nil, err)

	encoded, err := c.Encrypt([]byte(token))
	assert.Equal(t, nil, err)

	decoded, err := c.Decrypt(encoded)
	assert.Equal(t, nil, err)

	assert.NotEqual(t, []byte(token), encoded)
	assert.Equal(t, []byte(token), decoded)
}

func TestEncryptAndDecrypt(t *testing.T) {
	var err error

	// Test our 3 cipher types
	for _, initCipher := range []func([]byte) (Cipher, error){NewCipher, NewCFBCipher, NewGCMCipher} {
		// Test all 3 valid AES sizes
		for _, secretSize := range []int{16, 24, 32} {
			secret := make([]byte, secretSize)
			_, err = io.ReadFull(rand.Reader, secret)
			assert.Equal(t, nil, err)

			c, err := initCipher(secret)
			assert.Equal(t, nil, err)

			// Test various sizes sessions might be
			for _, dataSize := range []int{10, 100, 1000, 5000, 10000} {
				data := make([]byte, dataSize)
				_, err := io.ReadFull(rand.Reader, data)
				assert.Equal(t, nil, err)

				encrypted, err := c.Encrypt(data)
				assert.Equal(t, nil, err)
				assert.NotEqual(t, encrypted, data)

				decrypted, err := c.Decrypt(encrypted)
				assert.Equal(t, nil, err)
				assert.Equal(t, data, decrypted)
				assert.NotEqual(t, encrypted, decrypted)
			}
		}
	}
}

func TestDecryptWrongSecret(t *testing.T) {
	secret1 := []byte("0123456789abcdefghijklmnopqrstuv")
	secret2 := []byte("9876543210abcdefghijklmnopqrstuv")

	// Test CFB & Base64 (GCM is authenticated, it errors differently)
	for _, initCipher := range []func([]byte) (Cipher, error){NewCipher, NewCFBCipher} {
		c1, err := initCipher(secret1)
		assert.Equal(t, nil, err)

		c2, err := initCipher(secret2)
		assert.Equal(t, nil, err)

		data := []byte("f3928pufm982374dj02y485dsl34890u2t9nd4028s94dm58y2394087dhmsyt29h8df")

		ciphertext, err := c1.Encrypt(data)
		assert.Equal(t, nil, err)

		wrongData, err := c2.Decrypt(ciphertext)
		assert.Equal(t, nil, err)
		assert.NotEqual(t, data, wrongData)
	}
}

func TestDecryptGCMWrongSecret(t *testing.T) {
	secret1 := []byte("0123456789abcdefghijklmnopqrstuv")
	secret2 := []byte("9876543210abcdefghijklmnopqrstuv")

	c1, err := NewGCMCipher(secret1)
	assert.Equal(t, nil, err)

	c2, err := NewGCMCipher(secret2)
	assert.Equal(t, nil, err)

	data := []byte("f3928pufm982374dj02y485dsl34890u2t9nd4028s94dm58y2394087dhmsyt29h8df")

	ciphertext, err := c1.Encrypt(data)
	assert.Equal(t, nil, err)

	// GCM is authenticated - this should lead to message authentication failed
	_, err = c2.Decrypt(ciphertext)
	assert.Error(t, err)
}

func TestIntermixCiphersErrors(t *testing.T) {
	var err error

	// Encrypt with GCM, Decrypt with CFB: Results in Garbage data
	// Test all 3 valid AES sizes
	for _, secretSize := range []int{16, 24, 32} {
		secret := make([]byte, secretSize)
		_, err = io.ReadFull(rand.Reader, secret)
		assert.Equal(t, nil, err)

		gcm, err := NewGCMCipher(secret)
		assert.Equal(t, nil, err)

		cfb, err := NewCFBCipher(secret)
		assert.Equal(t, nil, err)

		// Test various sizes sessions might be
		for _, dataSize := range []int{10, 100, 1000, 5000, 10000} {
			data := make([]byte, dataSize)
			_, err := io.ReadFull(rand.Reader, data)
			assert.Equal(t, nil, err)

			encrypted, err := gcm.Encrypt(data)
			assert.Equal(t, nil, err)
			assert.NotEqual(t, encrypted, data)

			decrypted, err := cfb.Decrypt(encrypted)
			assert.Equal(t, nil, err)
			// Data is mangled
			assert.NotEqual(t, data, decrypted)
			assert.NotEqual(t, encrypted, decrypted)
		}
	}

	// Encrypt with CFB, Decrypt with GCM: Results in errors
	// Test all 3 valid AES sizes
	for _, secretSize := range []int{16, 24, 32} {
		secret := make([]byte, secretSize)
		_, err = io.ReadFull(rand.Reader, secret)
		assert.Equal(t, nil, err)

		gcm, err := NewGCMCipher(secret)
		assert.Equal(t, nil, err)

		cfb, err := NewCFBCipher(secret)
		assert.Equal(t, nil, err)

		// Test various sizes sessions might be
		for _, dataSize := range []int{10, 100, 1000, 5000, 10000} {
			data := make([]byte, dataSize)
			_, err := io.ReadFull(rand.Reader, data)
			assert.Equal(t, nil, err)

			encrypted, err := cfb.Encrypt(data)
			assert.Equal(t, nil, err)
			assert.NotEqual(t, encrypted, data)

			// GCM is authenticated - this should lead to message authentication failed
			_, err = gcm.Decrypt(encrypted)
			assert.Error(t, err)
		}
	}
}

func TestEncodeIntoAndDecodeIntoAccessToken(t *testing.T) {
	const secret = "0123456789abcdefghijklmnopqrstuv"
	c, err := NewCipher([]byte(secret))
	assert.Equal(t, nil, err)

	token := "my access token"
	originalToken := token

	assert.Equal(t, nil, c.EncryptInto(&token))
	assert.NotEqual(t, originalToken, token)

	assert.Equal(t, nil, c.DecryptInto(&token))
	assert.Equal(t, originalToken, token)

	// Check no errors with empty or nil strings
	empty := ""
	assert.Equal(t, nil, c.EncryptInto(&empty))
	assert.Equal(t, nil, c.DecryptInto(&empty))
	assert.Equal(t, nil, c.EncryptInto(nil))
	assert.Equal(t, nil, c.DecryptInto(nil))
}
