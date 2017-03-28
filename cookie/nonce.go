package cookie

import (
	"crypto/rand"
	"fmt"
)

func Nonce() (nonce string, err error) {
	b := make([]byte, 16)
	_, err = rand.Read(b)
	if err != nil {
		return
	}
	nonce = fmt.Sprintf("%x", b)
	return
}
