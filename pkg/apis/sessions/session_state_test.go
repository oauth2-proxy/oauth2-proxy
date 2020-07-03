package sessions_test

import (
	"crypto/rand"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/encryption"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/sessions/tests"
	"github.com/stretchr/testify/assert"
)

func timePtr(t time.Time) *time.Time {
	return &t
}

func TestIsExpired(t *testing.T) {
	s := &sessions.SessionState{ExpiresOn: timePtr(time.Now().Add(time.Duration(-1) * time.Minute))}
	assert.Equal(t, true, s.IsExpired())

	s = &sessions.SessionState{ExpiresOn: timePtr(time.Now().Add(time.Duration(1) * time.Minute))}
	assert.Equal(t, false, s.IsExpired())

	s = &sessions.SessionState{}
	assert.Equal(t, false, s.IsExpired())
}

func TestAge(t *testing.T) {
	ss := &sessions.SessionState{}

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

	// Tokens in the test table are purposefully redundant
	// Otherwise compressing small payloads could result in a compressed value
	// that is larger (compression dictionary + limited like strings to compress)
	// which breaks the len(compressed) < len(uncompressed) assertion.
	testCases := map[string]sessions.SessionState{
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

	for _, secretSize := range []int{16, 24, 32} {
		t.Run(fmt.Sprintf("%d byte secret", secretSize), func(t *testing.T) {
			secret := make([]byte, secretSize)
			_, err := io.ReadFull(rand.Reader, secret)
			assert.NoError(t, err)

			cfb, err := encryption.NewCFBCipher([]byte(secret))
			assert.NoError(t, err)
			gcm, err := encryption.NewGCMCipher([]byte(secret))
			assert.NoError(t, err)

			ciphers := map[string]encryption.Cipher{
				"CFB cipher": cfb,
				"GCM cipher": gcm,
			}

			for cipherName, c := range ciphers {
				t.Run(cipherName, func(t *testing.T) {
					for testName, ss := range testCases {
						t.Run(testName, func(t *testing.T) {
							encoded, err := ss.EncodeSessionState(c, false)
							assert.NoError(t, err)
							encodedCompressed, err := ss.EncodeSessionState(c, true)
							assert.NoError(t, err)
							// Make sure compressed version is smaller than if not compressed
							assert.Greater(t, len(encoded), len(encodedCompressed))

							decoded, err := sessions.DecodeSessionState(encoded, c, false)
							assert.NoError(t, err)
							decodedCompressed, err := sessions.DecodeSessionState(encodedCompressed, c, true)
							assert.NoError(t, err)

							compareSessionStates(t, decoded, decodedCompressed)
							compareSessionStates(t, decoded, &ss)
						})
					}
				})
			}

			t.Run("Mixed cipher types cause errors", func(t *testing.T) {
				for testName, ss := range testCases {
					t.Run(testName, func(t *testing.T) {
						cfbEncoded, err := ss.EncodeSessionState(cfb, false)
						assert.NoError(t, err)
						_, err = sessions.DecodeSessionState(cfbEncoded, gcm, false)
						assert.Error(t, err)

						gcmEncoded, err := ss.EncodeSessionState(gcm, false)
						assert.NoError(t, err)
						_, err = sessions.DecodeSessionState(gcmEncoded, cfb, false)
						assert.Error(t, err)
					})
				}
			})
		})
	}
}

// TestLegacyV5DecodeSessionState confirms V5 JSON sessions decode
func TestLegacyV5DecodeSessionState(t *testing.T) {
	testCases, cipher, legacyCipher := tests.CreateLegacyV5TestCases(t)

	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			// Legacy sessions fail in DecodeSessionState which results in
			// the fallback to LegacyV5DecodeSessionState
			_, err := sessions.DecodeSessionState([]byte(tc.Input), cipher, false)
			assert.Error(t, err)
			_, err = sessions.DecodeSessionState([]byte(tc.Input), cipher, true)
			assert.Error(t, err)

			ss, err := sessions.LegacyV5DecodeSessionState(tc.Input, legacyCipher)
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

func compareSessionStates(t *testing.T, expected *sessions.SessionState, actual *sessions.SessionState) {
	if expected.CreatedAt != nil {
		assert.NotNil(t, actual.CreatedAt)
		assert.Equal(t, true, expected.CreatedAt.Equal(*actual.CreatedAt))
	} else {
		assert.Nil(t, actual.CreatedAt)
	}
	if expected.ExpiresOn != nil {
		assert.NotNil(t, actual.ExpiresOn)
		assert.Equal(t, true, expected.ExpiresOn.Equal(*actual.ExpiresOn))
	} else {
		assert.Nil(t, actual.ExpiresOn)
	}

	// Compare sessions without *time.Time fields
	exp := *expected
	exp.CreatedAt = nil
	exp.ExpiresOn = nil
	act := *actual
	act.CreatedAt = nil
	act.ExpiresOn = nil
	assert.Equal(t, exp, act)
}
