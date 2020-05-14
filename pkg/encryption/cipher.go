package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// SecretBytes attempts to base64 decode the secret, if that fails it treats the secret as binary
func SecretBytes(secret string) []byte {
	b, err := base64.URLEncoding.DecodeString(addPadding(secret))
	if err == nil {
		return []byte(addPadding(string(b)))
	}
	return []byte(secret)
}

func addPadding(secret string) string {
	padding := len(secret) % 4
	switch padding {
	case 1:
		return secret + "==="
	case 2:
		return secret + "=="
	case 3:
		return secret + "="
	default:
		return secret
	}
}

// cookies are stored in a 3 part (value + timestamp + signature) to enforce that the values are as originally set.
// additionally, the 'value' is encrypted so it's opaque to the browser

// Validate ensures a cookie is properly signed
func Validate(cookie *http.Cookie, hmacKey []byte, expiration time.Duration) (value string, t time.Time, ok bool) {
	// value, timestamp, sig
	parts := strings.Split(cookie.Value, "|")
	if len(parts) != 3 {
		return
	}

	if checkSignature(parts[2], hmacKey, cookie.Name, parts[0], parts[1]) {
		ts, err := strconv.Atoi(parts[1])
		if err != nil {
			return
		}
		// The expiration timestamp set when the cookie was created
		// isn't sent back by the browser. Hence, we check whether the
		// creation timestamp stored in the cookie falls within the
		// window defined by (Now()-expiration, Now()].
		t = time.Unix(int64(ts), 0)
		if t.After(time.Now().Add(expiration*-1)) && t.Before(time.Now().Add(time.Minute*5)) {
			// it's a valid cookie. now get the contents
			rawValue, err := base64.URLEncoding.DecodeString(parts[0])
			if err == nil {
				value = string(rawValue)
				ok = true
				return
			}
		}
	}
	return
}

// SignedValue returns a cookie that is signed and can later be checked with Validate
func SignedValue(hmacKey []byte, name string, value string, now time.Time) string {
	encodedValue := base64.URLEncoding.EncodeToString([]byte(value))
	timeStr := fmt.Sprintf("%d", now.Unix())
	mac := cookieHMAC(sha256.New, hmacKey, name, encodedValue, timeStr)
	cookieVal := fmt.Sprintf("%s|%s|%s", encodedValue, timeStr, base64.URLEncoding.EncodeToString(mac))
	return cookieVal
}

func cookieHMAC(hasher func() hash.Hash, hmacKey []byte, args ...string) []byte {
	h := hmac.New(hasher, hmacKey)
	for _, arg := range args {
		h.Write([]byte(arg))
	}
	return h.Sum(nil)
}

func hmacToSignature(mac []byte) string {
	return base64.URLEncoding.EncodeToString(mac)
}

func checkSignature(signature string, hmacKey []byte, args ...string) bool {

	providedMAC, err := base64.URLEncoding.DecodeString(signature)
	if err != nil {
		return false
	}

	expectedMAC := cookieHMAC(sha256.New, hmacKey, args...)
	if hmac.Equal(providedMAC, expectedMAC) {
		return true
	}

	// TODO: After appropriate rollout window, remove support for legacy SHA1
	expectedMAC = cookieHMAC(sha1.New, hmacKey, args...)
	return hmac.Equal(providedMAC, expectedMAC)
}

// Cipher provides methods to encrypt and decrypt cookie values
type Cipher struct {
	cipher.Block
}

// NewCipher returns a new aes Cipher for encrypting cookie values
func NewCipher(secret []byte) (*Cipher, error) {
	c, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	return &Cipher{Block: c}, err
}

// Encrypt a value for use in a cookie
func (c *Cipher) Encrypt(value string) (string, error) {
	ciphertext := make([]byte, aes.BlockSize+len(value))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("failed to create initialization vector %s", err)
	}

	stream := cipher.NewCFBEncrypter(c.Block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(value))
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt a value from a cookie to it's original string
func (c *Cipher) Decrypt(s string) (string, error) {
	encrypted, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt cookie value %s", err)
	}

	if len(encrypted) < aes.BlockSize {
		return "", fmt.Errorf("encrypted cookie value should be "+
			"at least %d bytes, but is only %d bytes",
			aes.BlockSize, len(encrypted))
	}

	iv := encrypted[:aes.BlockSize]
	encrypted = encrypted[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(c.Block, iv)
	stream.XORKeyStream(encrypted, encrypted)

	return string(encrypted), nil
}
