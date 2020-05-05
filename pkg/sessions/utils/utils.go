package utils

import (
	"encoding/base64"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/encryption"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/sessions/utils/envelope"
)

// CookieForSession serializes a session state for storage in a cookie
func CookieForSession(s *sessions.SessionState, c *encryption.Cipher) (string, error) {
	return s.EncodeSessionState(c)
}

// SessionFromCookie deserializes a session from a cookie value
func SessionFromCookie(v string, c *encryption.Cipher) (s *sessions.SessionState, err error) {
	return sessions.DecodeSessionState(v, c)
}

// CompressedCookieForSession serializes an lz4 compressed session state for storage in a cookie
func CompressedCookieForSession(s *sessions.SessionState, c *encryption.Cipher, level int) ([]byte, error) {
	compressed, err := s.CompressedSessionState(level)
	if err != nil {
		return []byte{}, err
	}
	encrypted, err := c.EncryptCFB(compressed)
	if err != nil {
		return []byte{}, err
	}
	se := &SessionEnvelope{
		Type:       envelope.CookieType,
		Encryption: envelope.CFBEncryption,
		Compressed: true,
		Data:       encrypted,
	}
	value, err := se.Marshal()
	if err != nil {
		return []byte{}, err
	}
	return value, nil
}

// SessionFromCompressedCookie deserializes a session from a compressed cookie value
func SessionFromCompressedCookie(v []byte, c *encryption.Cipher) (*sessions.SessionState, error) {
	var (
		se  *SessionEnvelope
		ss  *sessions.SessionState
		err error
	)

	se, err = UnmarshalSessionEnvelope(v)
	if err != nil {
		// If we fail, assume an uncompressed cookie was passed
		return sessions.DecodeSessionState(string(v), c)
	}

	// Future: allows differing encryption algorithms
	if se.Encryption == envelope.CFBEncryption {
		se.Data, err = c.DecryptCFB(se.Data)
		if err != nil {
			return nil, err
		}
	}

	// We assume data in this method is compressed
	ss, err = sessions.DecompressSessionState(se.Data)
	if err != nil {
		return nil, err
	}
	return ss, nil
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
