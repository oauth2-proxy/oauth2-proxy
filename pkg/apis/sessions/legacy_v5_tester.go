package sessions

import (
	"fmt"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/encryption"
	"github.com/stretchr/testify/assert"
)

const LegacyV5TestSecret = "0123456789abcdefghijklmnopqrstuv"

// LegacyV5TestCase provides V5 JSON based test cases for legacy fallback code
type LegacyV5TestCase struct {
	Input  string
	Error  bool
	Output *SessionState
}

// CreateLegacyV5TestCases makes various V5 JSON sessions as test cases
//
// Used for `apis/sessions/session_state_test.go` & `sessions/redis/redis_store_test.go`
//
// TODO: Remove when this is deprecated (likely V7)
func CreateLegacyV5TestCases(t *testing.T) (map[string]LegacyV5TestCase, encryption.Cipher, encryption.Cipher) {
	created := time.Now()
	createdJSON, err := created.MarshalJSON()
	assert.NoError(t, err)
	createdString := string(createdJSON)
	e := time.Now().Add(time.Duration(1) * time.Hour)
	eJSON, err := e.MarshalJSON()
	assert.NoError(t, err)
	eString := string(eJSON)

	cfbCipher, err := encryption.NewCFBCipher([]byte(LegacyV5TestSecret))
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
			Output: &SessionState{
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
			Output: &SessionState{
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
