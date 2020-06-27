package sessions

import (
	"crypto/rand"
	"fmt"
	"io"
	mathrand "math/rand"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/encryption"
	"github.com/stretchr/testify/assert"
)

const secret = "0123456789abcdefghijklmnopqrstuv"

func timePtr(t time.Time) *time.Time {
	return &t
}

func TestIsExpired(t *testing.T) {
	s := &SessionState{ExpiresOn: timePtr(time.Now().Add(time.Duration(-1) * time.Minute))}
	assert.Equal(t, true, s.IsExpired())

	s = &SessionState{ExpiresOn: timePtr(time.Now().Add(time.Duration(1) * time.Minute))}
	assert.Equal(t, false, s.IsExpired())

	s = &SessionState{}
	assert.Equal(t, false, s.IsExpired())
}

func TestAge(t *testing.T) {
	ss := &SessionState{}

	// Created at unset so should be 0
	assert.Equal(t, time.Duration(0), ss.Age())

	// Set CreatedAt to 1 hour ago
	ss.CreatedAt = timePtr(time.Now().Add(-1 * time.Hour))
	assert.Equal(t, time.Hour, ss.Age().Round(time.Minute))
}

// TestEncodeAndDecodeSessionState encodes & decodes various session states
// and confirms the operation is 1:1
func TestEncodeAndDecodeSessionState(t *testing.T) {
	created := time.Now()
	expires := time.Now().Add(time.Duration(1) * time.Hour)

	c, err := encryption.NewCFBCipher([]byte(secret))
	assert.NoError(t, err)

	// Tokens in the test table are purposefully redundant
	// Otherwise compressing small payloads could result in a compressed value
	// that is larger (compression dictionary + limited like string to compress)
	// which breaks the len(compressed) <= len(uncompressed) assertion.
	testCases := map[string]SessionState{
		"Full session": {
			Email:             "username@example.com",
			User:              "username",
			PreferredUsername: "preferred.username",
			AccessToken:       "AccessToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
			IDToken:           "IDToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
			CreatedAt:         &created,
			ExpiresOn:         &expires,
			RefreshToken:      "RefreshToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
		},
		"No ExpiresOn": {
			Email:             "username@example.com",
			User:              "username",
			PreferredUsername: "preferred.username",
			AccessToken:       "AccessToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
			IDToken:           "IDToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
			CreatedAt:         &created,
			RefreshToken:      "RefreshToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
		},
		"No PreferredUsername": {
			Email:        "username@example.com",
			User:         "username",
			AccessToken:  "AccessToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
			IDToken:      "IDToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
			CreatedAt:    &created,
			ExpiresOn:    &expires,
			RefreshToken: "RefreshToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
		},
		"Minimal session": {
			User:         "username",
			IDToken:      "IDToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
			CreatedAt:    &created,
			RefreshToken: "RefreshToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
		},
		"Bearer authorization header created session": {
			Email:       "username",
			User:        "username",
			AccessToken: "IDToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
			IDToken:     "IDToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
			ExpiresOn:   &expires,
		},
	}

	for name, ss := range testCases {
		t.Run(name, func(t *testing.T) {
			encoded, err := ss.EncodeSessionState(c, false)
			assert.NoError(t, err)
			encodedCompressed, err := ss.EncodeSessionState(c, true)
			assert.NoError(t, err)
			assert.GreaterOrEqual(t, len(encoded), len(encodedCompressed))

			decoded, err := DecodeSessionState(encoded, c, false)
			assert.NoError(t, err)
			decodedCompressed, err := DecodeSessionState(encodedCompressed, c, true)
			assert.NoError(t, err)

			compareSessionStates(t, decoded, decodedCompressed)
			compareSessionStates(t, decoded, &ss)
		})
	}
}

// TestLegacyV5DecodeSessionState confirms V5 JSON sessions decode
func TestLegacyV5DecodeSessionState(t *testing.T) {
	created := time.Now()
	createdJSON, err := created.MarshalJSON()
	assert.NoError(t, err)
	createdString := string(createdJSON)
	e := time.Now().Add(time.Duration(1) * time.Hour)
	eJSON, err := e.MarshalJSON()
	assert.NoError(t, err)
	eString := string(eJSON)

	cipher, err := encryption.NewCFBCipher([]byte(secret))
	assert.NoError(t, err)
	legacyCipher := encryption.NewBase64Cipher(cipher)

	testCases := map[string]struct {
		Input  string
		Error  bool
		Output *SessionState
	}{
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

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			// Legacy sessions fail in DecodeSessionState which results in
			// the fallback to LegacyV5DecodeSessionState
			_, err = DecodeSessionState([]byte(tc.Input), cipher, false)
			assert.Error(t, err)
			_, err = DecodeSessionState([]byte(tc.Input), cipher, true)
			assert.Error(t, err)

			ss, err := LegacyV5DecodeSessionState(tc.Input, legacyCipher)
			if tc.Error {
				assert.Error(t, err)
				assert.Nil(t, ss)
				return
			}
			assert.NoError(t, err)
			compareSessionStates(t, tc.Output, ss)
		})
	}
}

func TestIntoEncryptAndIntoDecrypt(t *testing.T) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// Test all 3 valid AES sizes
	for _, secretSize := range []int{16, 24, 32} {
		t.Run(fmt.Sprintf("%d", secretSize), func(t *testing.T) {
			secret := make([]byte, secretSize)
			_, err := io.ReadFull(rand.Reader, secret)
			assert.Equal(t, nil, err)

			cfb, err := encryption.NewCFBCipher([]byte(secret))
			assert.NoError(t, err)
			c := encryption.NewBase64Cipher(cfb)

			// Check no errors with empty or nil strings
			empty := ""
			assert.Equal(t, nil, into(&empty, c.Encrypt))
			assert.Equal(t, nil, into(&empty, c.Decrypt))
			assert.Equal(t, nil, into(nil, c.Encrypt))
			assert.Equal(t, nil, into(nil, c.Decrypt))

			// Test various sizes tokens might be
			for _, dataSize := range []int{10, 100, 1000, 5000, 10000} {
				t.Run(fmt.Sprintf("%d", dataSize), func(t *testing.T) {
					b := make([]byte, dataSize)
					for i := range b {
						b[i] = charset[mathrand.Intn(len(charset))]
					}
					data := string(b)
					originalData := data

					assert.Equal(t, nil, into(&data, c.Encrypt))
					assert.NotEqual(t, originalData, data)

					assert.Equal(t, nil, into(&data, c.Decrypt))
					assert.Equal(t, originalData, data)
				})
			}
		})
	}
}

func compareSessionStates(t *testing.T, left *SessionState, right *SessionState) {
	if left.CreatedAt != nil {
		assert.NotNil(t, right.CreatedAt)
		assert.Equal(t, true, left.CreatedAt.Equal(*right.CreatedAt))
	} else {
		assert.Nil(t, right.CreatedAt)
	}
	if left.ExpiresOn != nil {
		assert.NotNil(t, right.ExpiresOn)
		assert.Equal(t, true, left.ExpiresOn.Equal(*right.ExpiresOn))
	} else {
		assert.Nil(t, right.ExpiresOn)
	}

	// Compare sessions without *time.Time fields
	l := *left
	l.CreatedAt = nil
	l.ExpiresOn = nil
	r := *right
	r.CreatedAt = nil
	r.ExpiresOn = nil
	assert.Equal(t, l, r)
}
