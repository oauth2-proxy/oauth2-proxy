package encryption

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"

	"golang.org/x/crypto/blake2b"
)

// Nonce generates a random 32-byte slice to be used as a nonce
func Nonce() ([]byte, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// HashNonce returns the BLAKE2b 256-bit hash of a nonce
// NOTE: Error checking (G104) is purposefully skipped:
// - `blake2b.New256` has no error path with a nil signing key
// - `hash.Hash` interface's `Write` has an error signature, but
//   `blake2b.digest.Write` does not use it.
/* #nosec G104 */
func HashNonce(nonce []byte) string {
	hasher, _ := blake2b.New256(nil)
	hasher.Write(nonce)
	sum := hasher.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(sum)
}

// CheckNonce tests if a nonce matches the hashed version of it
func CheckNonce(nonce []byte, hashed string) bool {
	return hmac.Equal([]byte(HashNonce(nonce)), []byte(hashed))
}
