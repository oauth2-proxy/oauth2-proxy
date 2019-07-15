package utils

import (
	"encoding/base64"

	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/encryption"
)

// CookieForSession serializes a session state for storage in a cookie
func CookieForSession(s *sessions.SessionState, c *encryption.Cipher) (string, error) {
	return s.EncodeSessionState(c)
}

// SessionFromCookie deserializes a session from a cookie value
func SessionFromCookie(v string, c *encryption.Cipher) (s *sessions.SessionState, err error) {
	return sessions.DecodeSessionState(v, c)
}

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
