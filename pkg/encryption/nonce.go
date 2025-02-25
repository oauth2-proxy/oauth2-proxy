package encryption

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// Nonce generates a random n-byte slice
func Nonce(length int) ([]byte, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// HashNonce returns the SHA256 hash of a nonce
func HashNonce(nonce []byte) string {
	if nonce == nil {
		return ""
	}

	hasher := sha256.New()
	hasher.Write(nonce)
	sum := hasher.Sum(nil)

	return base64.RawURLEncoding.EncodeToString(sum)
}

// CheckNonce tests if a nonce matches the hashed version of it
func CheckNonce(nonce []byte, hashed string) bool {
	return hmac.Equal([]byte(HashNonce(nonce)), []byte(hashed))
}
