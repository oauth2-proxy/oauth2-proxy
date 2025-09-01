package encryption

import (
	"crypto/hmac"
	"crypto/rand"
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

const (
	CodeChallengeMethodPlain = "plain"
	CodeChallengeMethodS256  = "S256"
	asciiCharset             = "-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz~"
)

// SecretBytes attempts to base64 decode the secret, if that fails it treats the secret as binary
func SecretBytes(secret string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(secret, "="))
	if err == nil {
		// Only return decoded form if a valid AES length
		// Don't want unintentional decoding resulting in invalid lengths confusing a user
		// that thought they used a 16, 24, 32 length string
		for _, i := range []int{16, 24, 32} {
			if len(b) == i {
				return b
			}
		}
	}
	// If decoding didn't work or resulted in non-AES compliant length,
	// assume the raw string was the intended secret
	return []byte(secret)
}

// cookies are stored in a 3 part (value + timestamp + signature) to enforce that the values are as originally set.
// additionally, the 'value' is encrypted so it's opaque to the browser

// Validate ensures a cookie is properly signed
func Validate(cookie *http.Cookie, seed string, expiration time.Duration) (value []byte, t time.Time, ok bool) {
	// value, timestamp, sig
	parts := strings.Split(cookie.Value, "|")
	if len(parts) != 3 {
		return
	}
	if checkSignature(parts[2], seed, cookie.Name, parts[0], parts[1]) {
		ts, err := strconv.Atoi(parts[1])
		if err != nil {
			return
		}
		// The expiration timestamp set when the cookie was created
		// isn't sent back by the browser. Hence, we check whether the
		// creation timestamp stored in the cookie falls within the
		// window defined by (Now()-expiration, Now()].
		t = time.Unix(int64(ts), 0)
		if (expiration == time.Duration(0)) || (t.After(time.Now().Add(expiration*-1)) && t.Before(time.Now().Add(time.Minute*5))) {
			// it's a valid cookie. now get the contents
			rawValue, err := base64.URLEncoding.DecodeString(parts[0])
			if err == nil {
				value = rawValue
				ok = true
				return
			}
		}
	}
	return
}

// SignedValue returns a cookie that is signed and can later be checked with Validate
func SignedValue(seed string, key string, value []byte, now time.Time) (string, error) {
	encodedValue := base64.URLEncoding.EncodeToString(value)
	timeStr := fmt.Sprintf("%d", now.Unix())
	sig, err := cookieSignature(sha256.New, seed, key, encodedValue, timeStr)
	if err != nil {
		return "", err
	}
	cookieVal := fmt.Sprintf("%s|%s|%s", encodedValue, timeStr, sig)
	return cookieVal, nil
}

// GenerateCodeVerifierString returns a base64 encoded string of n random bytes
func GenerateCodeVerifierString(n int) (string, error) {
	data := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		return "", err
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(data), nil
}

func GenerateCodeChallenge(method, codeVerifier string) (string, error) {
	switch method {
	case CodeChallengeMethodPlain:
		return codeVerifier, nil
	case CodeChallengeMethodS256:
		shaSum := sha256.Sum256([]byte(codeVerifier))
		return base64.RawURLEncoding.EncodeToString(shaSum[:]), nil
	default:
		return "", fmt.Errorf("unknown challenge method: %v", method)
	}
}

func cookieSignature(signer func() hash.Hash, args ...string) (string, error) {
	h := hmac.New(signer, []byte(args[0]))
	for _, arg := range args[1:] {
		_, err := h.Write([]byte(arg))
		if err != nil {
			return "", err
		}
	}
	var b []byte
	b = h.Sum(b)
	return base64.URLEncoding.EncodeToString(b), nil
}

func checkSignature(signature string, args ...string) bool {
	checkSig, err := cookieSignature(sha256.New, args...)
	if err != nil {
		return false
	}
	return checkHmac(signature, checkSig)
}

func checkHmac(input, expected string) bool {
	inputMAC, err1 := base64.URLEncoding.DecodeString(input)
	if err1 == nil {
		expectedMAC, err2 := base64.URLEncoding.DecodeString(expected)
		if err2 == nil {
			return hmac.Equal(inputMAC, expectedMAC)
		}
	}
	return false
}
