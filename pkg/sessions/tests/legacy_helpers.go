package tests

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/encryption"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/sessions/redis"
	"github.com/stretchr/testify/assert"
)

// LegacyStoreValue implements the legacy V5 Redis store AES-CFB value encryption
func LegacyStoreValue(value string, ticket *redis.TicketData) ([]byte, error) {
	ciphertext := make([]byte, len(value))
	block, err := aes.NewCipher(ticket.Secret)
	if err != nil {
		return nil, fmt.Errorf("error initiating cipher block %s", err)
	}

	// Use secret as the Initialization Vector too, because each entry has it's own key
	stream := cipher.NewCFBEncrypter(block, ticket.Secret)
	stream.XORKeyStream(ciphertext, []byte(value))

	return ciphertext, nil
}

// LegacyV5TestCase provides V5 JSON based test cases for legacy fallback code
type LegacyV5TestCase struct {
	Input  string
	Error  bool
	Output *sessions.SessionState
}

// CreateLegacyV5TestCases makes various V5 JSON sessions as test cases
func CreateLegacyV5TestCases(t *testing.T) (map[string]LegacyV5TestCase, encryption.Cipher, encryption.Cipher) {
	const secret = "0123456789abcdefghijklmnopqrstuv"

	created := time.Now()
	createdJSON, err := created.MarshalJSON()
	assert.NoError(t, err)
	createdString := string(createdJSON)
	e := time.Now().Add(time.Duration(1) * time.Hour)
	eJSON, err := e.MarshalJSON()
	assert.NoError(t, err)
	eString := string(eJSON)

	cfbCipher, err := encryption.NewCFBCipher([]byte(secret))
	assert.NoError(t, err)
	legacyCipher := encryption.NewBase64Cipher(cfbCipher)

	testCases := map[string]LegacyV5TestCase{
		"User & email unencrypted": {
			Input: `{"Email":"user@domain.com","User":"just-user"}`,
			Error: true,
		},
		"Only email unencrypted": {
			Input: `{"Email":"user@domain.com"}`,
			Error: true,
		},
		"Just user unencrypted": {
			Input: `{"User":"just-user"}`,
			Error: true,
		},
		"User and Email unencrypted while rest is encrypted": {
			Input: fmt.Sprintf(`{"Email":"user@domain.com","User":"just-user","AccessToken":"I6s+ml+/MldBMgHIiC35BTKTh57skGX24w==","IDToken":"xojNdyyjB1HgYWh6XMtXY/Ph5eCVxa1cNsklJw==","RefreshToken":"qEX0x6RmASxo4dhlBG6YuRs9Syn/e9sHu/+K","CreatedAt":%s,"ExpiresOn":%s}`, createdString, eString),
			Error: true,
		},
		"Full session with cipher": {
			Input: fmt.Sprintf(`{"Email":"FsKKYrTWZWrxSOAqA/fTNAUZS5QWCqOBjuAbBlbVOw==","User":"rT6JP3dxQhxUhkWrrd7yt6c1mDVyQCVVxw==","AccessToken":"I6s+ml+/MldBMgHIiC35BTKTh57skGX24w==","IDToken":"xojNdyyjB1HgYWh6XMtXY/Ph5eCVxa1cNsklJw==","RefreshToken":"qEX0x6RmASxo4dhlBG6YuRs9Syn/e9sHu/+K","CreatedAt":%s,"ExpiresOn":%s}`, createdString, eString),
			Output: &sessions.SessionState{
				Email:        "user@domain.com",
				User:         "just-user",
				AccessToken:  "token1234",
				IDToken:      "rawtoken1234",
				CreatedAt:    &created,
				ExpiresOn:    &e,
				RefreshToken: "refresh4321",
			},
		},
		"Minimal session encrypted with cipher": {
			Input: `{"Email":"EGTllJcOFC16b7LBYzLekaHAC5SMMSPdyUrg8hd25g==","User":"rT6JP3dxQhxUhkWrrd7yt6c1mDVyQCVVxw=="}`,
			Output: &sessions.SessionState{
				Email: "user@domain.com",
				User:  "just-user",
			},
		},
		"Unencrypted User, Email and AccessToken": {
			Input: `{"Email":"user@domain.com","User":"just-user","AccessToken":"X"}`,
			Error: true,
		},
		"Unencrypted User, Email and IDToken": {
			Input: `{"Email":"user@domain.com","User":"just-user","IDToken":"XXXX"}`,
			Error: true,
		},
	}

	return testCases, cfbCipher, legacyCipher
}
