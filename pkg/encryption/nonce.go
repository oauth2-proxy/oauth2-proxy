package encryption

import (
	"crypto/rand"
	"fmt"
)

// Nonce generates a random 16 byte string to be used as a nonce
func Nonce() (nonce string, err error) {
	b := make([]byte, 16)
	_, err = rand.Read(b)
	if err != nil {
		return
	}
	nonce = fmt.Sprintf("%x", b)
	return
}
