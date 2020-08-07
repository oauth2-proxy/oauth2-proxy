package sessions

import (
	"crypto/rand"
	"fmt"
	"io"
	mathrand "math/rand"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/encryption"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
)

func timePtr(t time.Time) *time.Time {
	return &t
}

func TestString(t *testing.T) {
	g := NewWithT(t)
	created, err := time.Parse(time.RFC3339, "2000-01-01T00:00:00Z")
	g.Expect(err).ToNot(HaveOccurred())
	expires, err := time.Parse(time.RFC3339, "2000-01-01T01:00:00Z")
	g.Expect(err).ToNot(HaveOccurred())

	testCases := []struct {
		name         string
		sessionState *SessionState
		expected     string
	}{
		{
			name: "Minimal Session",
			sessionState: &SessionState{
				Email:             "email@email.email",
				User:              "some.user",
				PreferredUsername: "preferred.user",
			},
			expected: "Session{email:email@email.email user:some.user PreferredUsername:preferred.user}",
		},
		{
			name: "Full Session",
			sessionState: &SessionState{
				Email:             "email@email.email",
				User:              "some.user",
				PreferredUsername: "preferred.user",
				CreatedAt:         &created,
				ExpiresOn:         &expires,
				AccessToken:       "access.token",
				IDToken:           "id.token",
				RefreshToken:      "refresh.token",
			},
			expected: "Session{email:email@email.email user:some.user PreferredUsername:preferred.user token:true id_token:true created:2000-01-01 00:00:00 +0000 UTC expires:2000-01-01 01:00:00 +0000 UTC refresh_token:true}",
		},
		{
			name: "With a CreatedAt",
			sessionState: &SessionState{
				Email:             "email@email.email",
				User:              "some.user",
				PreferredUsername: "preferred.user",
				CreatedAt:         &created,
			},
			expected: "Session{email:email@email.email user:some.user PreferredUsername:preferred.user created:2000-01-01 00:00:00 +0000 UTC}",
		},
		{
			name: "With an ExpiresOn",
			sessionState: &SessionState{
				Email:             "email@email.email",
				User:              "some.user",
				PreferredUsername: "preferred.user",
				ExpiresOn:         &expires,
			},
			expected: "Session{email:email@email.email user:some.user PreferredUsername:preferred.user expires:2000-01-01 01:00:00 +0000 UTC}",
		},
		{
			name: "With an AccessToken",
			sessionState: &SessionState{
				Email:             "email@email.email",
				User:              "some.user",
				PreferredUsername: "preferred.user",
				AccessToken:       "access.token",
			},
			expected: "Session{email:email@email.email user:some.user PreferredUsername:preferred.user token:true}",
		},
		{
			name: "With an IDToken",
			sessionState: &SessionState{
				Email:             "email@email.email",
				User:              "some.user",
				PreferredUsername: "preferred.user",
				IDToken:           "id.token",
			},
			expected: "Session{email:email@email.email user:some.user PreferredUsername:preferred.user id_token:true}",
		},
		{
			name: "With a RefreshToken",
			sessionState: &SessionState{
				Email:             "email@email.email",
				User:              "some.user",
				PreferredUsername: "preferred.user",
				RefreshToken:      "refresh.token",
			},
			expected: "Session{email:email@email.email user:some.user PreferredUsername:preferred.user refresh_token:true}",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gs := NewWithT(t)
			gs.Expect(tc.sessionState.String()).To(Equal(tc.expected))
		})
	}
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

	// Tokens in the test table are purposefully redundant
	// Otherwise compressing small payloads could result in a compressed value
	// that is larger (compression dictionary + limited like strings to compress)
	// which breaks the len(compressed) < len(uncompressed) assertion.
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

							decoded, err := DecodeSessionState(encoded, c, false)
							assert.NoError(t, err)
							decodedCompressed, err := DecodeSessionState(encodedCompressed, c, true)
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
						_, err = DecodeSessionState(cfbEncoded, gcm, false)
						assert.Error(t, err)

						gcmEncoded, err := ss.EncodeSessionState(gcm, false)
						assert.NoError(t, err)
						_, err = DecodeSessionState(gcmEncoded, cfb, false)
						assert.Error(t, err)
					})
				}
			})
		})
	}
}

// TestLegacyV5DecodeSessionState confirms V5 JSON sessions decode
//
// TODO: Remove when this is deprecated (likely V7)
func TestLegacyV5DecodeSessionState(t *testing.T) {
	testCases, cipher, legacyCipher := CreateLegacyV5TestCases(t)

	for testName, tc := range testCases {
		t.Run(testName, func(t *testing.T) {
			// Legacy sessions fail in DecodeSessionState which results in
			// the fallback to LegacyV5DecodeSessionState
			_, err := DecodeSessionState([]byte(tc.Input), cipher, false)
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

// Test_into tests the into helper function used in LegacyV5DecodeSessionState
//
// TODO: Remove when this is deprecated (likely V7)
func Test_into(t *testing.T) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// Test all 3 valid AES sizes
	for _, secretSize := range []int{16, 24, 32} {
		t.Run(fmt.Sprintf("%d", secretSize), func(t *testing.T) {
			secret := make([]byte, secretSize)
			_, err := io.ReadFull(rand.Reader, secret)
			assert.Equal(t, nil, err)

			cfb, err := encryption.NewCFBCipher(secret)
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

func compareSessionStates(t *testing.T, expected *SessionState, actual *SessionState) {
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
