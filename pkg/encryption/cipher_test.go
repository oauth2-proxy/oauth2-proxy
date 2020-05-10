package encryption

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncodeAndDecodeAccessToken(t *testing.T) {
	const secret = "0123456789abcdefghijklmnopqrstuv"
	const token = "my access token"
	c, err := NewBase64Cipher(NewCFBCipher, []byte(secret))
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
	c, err := NewBase64Cipher(NewCFBCipher, []byte(secret))
	assert.Equal(t, nil, err)

	encoded, err := c.Encrypt([]byte(token))
	assert.Equal(t, nil, err)

	decoded, err := c.Decrypt(encoded)
	assert.Equal(t, nil, err)

	assert.NotEqual(t, []byte(token), encoded)
	assert.Equal(t, []byte(token), decoded)
}

func TestEncryptAndDecrypt(t *testing.T) {
	// Test our 2 cipher types
	for _, initCipher := range []func([]byte) (Cipher, error){NewCFBCipher, NewGCMCipher} {
		// Test all 3 valid AES sizes
		for _, secretSize := range []int{16, 24, 32} {
			secret := make([]byte, secretSize)
			_, err := io.ReadFull(rand.Reader, secret)
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

func TestEncryptAndDecryptBase64(t *testing.T) {
	// Test our cipher types wrapped in Base64 encoder
	for _, initCipher := range []func([]byte) (Cipher, error){NewCFBCipher, NewGCMCipher} {
		// Test all 3 valid AES sizes
		for _, secretSize := range []int{16, 24, 32} {
			secret := make([]byte, secretSize)
			_, err := io.ReadFull(rand.Reader, secret)
			assert.Equal(t, nil, err)

			c, err := NewBase64Cipher(initCipher, secret)
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

func TestDecryptCFBWrongSecret(t *testing.T) {
	secret1 := []byte("0123456789abcdefghijklmnopqrstuv")
	secret2 := []byte("9876543210abcdefghijklmnopqrstuv")

	c1, err := NewCFBCipher(secret1)
	assert.Equal(t, nil, err)

	c2, err := NewCFBCipher(secret2)
	assert.Equal(t, nil, err)

	data := []byte("f3928pufm982374dj02y485dsl34890u2t9nd4028s94dm58y2394087dhmsyt29h8df")

	ciphertext, err := c1.Encrypt(data)
	assert.Equal(t, nil, err)

	wrongData, err := c2.Decrypt(ciphertext)
	assert.Equal(t, nil, err)
	assert.NotEqual(t, data, wrongData)
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
	// Encrypt with GCM, Decrypt with CFB: Results in Garbage data
	// Test all 3 valid AES sizes
	for _, secretSize := range []int{16, 24, 32} {
		secret := make([]byte, secretSize)
		_, err := io.ReadFull(rand.Reader, secret)
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
		_, err := io.ReadFull(rand.Reader, secret)
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
