package sessions

import (
	"crypto/rand"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func timePtr(t time.Time) *time.Time {
	return &t
}

func TestCreatedAtNow(t *testing.T) {
	g := NewWithT(t)
	ss := &SessionState{}

	now := time.Unix(1234567890, 0)
	ss.Clock.Set(now)

	ss.CreatedAtNow()
	g.Expect(*ss.CreatedAt).To(Equal(now))
}

func TestExpiresIn(t *testing.T) {
	g := NewWithT(t)
	ss := &SessionState{}

	now := time.Unix(1234567890, 0)
	ss.Clock.Set(now)

	ttl := time.Duration(743) * time.Second
	ss.ExpiresIn(ttl)

	g.Expect(*ss.ExpiresOn).To(Equal(ss.CreatedAt.Add(ttl)))
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
			Nonce:             []byte("abcdef1234567890abcdef1234567890"),
		},
		"No ExpiresOn": {
			Email:             "username@example.com",
			User:              "username",
			PreferredUsername: "preferred.username",
			AccessToken:       "AccessToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
			IDToken:           "IDToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
			CreatedAt:         &created,
			RefreshToken:      "RefreshToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
			Nonce:             []byte("abcdef1234567890abcdef1234567890"),
		},
		"No PreferredUsername": {
			Email:        "username@example.com",
			User:         "username",
			AccessToken:  "AccessToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
			IDToken:      "IDToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
			CreatedAt:    &created,
			ExpiresOn:    &expires,
			RefreshToken: "RefreshToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
			Nonce:        []byte("abcdef1234567890abcdef1234567890"),
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
		"With groups": {
			Email:             "username@example.com",
			User:              "username",
			PreferredUsername: "preferred.username",
			AccessToken:       "AccessToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
			IDToken:           "IDToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
			CreatedAt:         &created,
			ExpiresOn:         &expires,
			RefreshToken:      "RefreshToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
			Nonce:             []byte("abcdef1234567890abcdef1234567890"),
			Groups:            []string{"group-a", "group-b"},
		},
		"With additional claims": {
			Email:             "username@example.com",
			User:              "username",
			PreferredUsername: "preferred.username",
			AccessToken:       "AccessToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
			IDToken:           "IDToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
			CreatedAt:         &created,
			ExpiresOn:         &expires,
			RefreshToken:      "RefreshToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
			Nonce:             []byte("abcdef1234567890abcdef1234567890"),
			Groups:            []string{"group-a", "group-b"},
			AdditionalClaims: map[string]interface{}{
				"custom_claim_1": "value1",
				"custom_claim_2": true,
				"custom_claim_3": int8(1),
				"custom_claim_4": []interface{}{"item1", "item2"},
			},
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
							require.NoError(t, err)
							encodedCompressed, err := ss.EncodeSessionState(c, true)
							require.NoError(t, err)
							// Make sure compressed version is smaller than if not compressed
							assert.Greater(t, len(encoded), len(encodedCompressed))

							decoded, err := DecodeSessionState(encoded, c, false)
							require.NoError(t, err)
							decodedCompressed, err := DecodeSessionState(encodedCompressed, c, true)
							require.NoError(t, err)

							compareSessionStates(t, decoded, decodedCompressed)
							compareSessionStates(t, decoded, &ss)
						})
					}
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

func TestGetClaim(t *testing.T) {
	createdAt := time.Now()
	expiresOn := createdAt.Add(1 * time.Hour)

	ss := &SessionState{
		CreatedAt:         &createdAt,
		ExpiresOn:         &expiresOn,
		AccessToken:       "AccessToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
		IDToken:           "IDToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
		RefreshToken:      "RefreshToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7",
		Email:             "user@example.com",
		User:              "user123",
		Groups:            []string{"group1", "group2"},
		PreferredUsername: "preferred_user",
		AdditionalClaims: map[string]interface{}{
			"custom_claim_1": "value1",
			"custom_claim_2": true,
			"custom_claim_3": 1,
			"custom_claim_4": []string{"item1", "item2"},
		},
	}

	tests := []struct {
		claim string
		want  []string
	}{
		{"access_token", []string{"AccessToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7"}},
		{"id_token", []string{"IDToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7"}},
		{"refresh_token", []string{"RefreshToken.12349871293847fdsaihf9238h4f91h8fr.1349f831y98fd7"}},
		{"created_at", []string{createdAt.String()}},
		{"expires_on", []string{expiresOn.String()}},
		{"email", []string{"user@example.com"}},
		{"user", []string{"user123"}},
		{"groups", []string{"group1", "group2"}},
		{"preferred_username", []string{"preferred_user"}},
		{"custom_claim_1", []string{"value1"}},
		{"custom_claim_2", []string{"true"}},
		{"custom_claim_3", []string{"1"}},
		{"custom_claim_4", []string{"item1", "item2"}},
	}

	for _, tt := range tests {
		t.Run(tt.claim, func(t *testing.T) {
			gs := NewWithT(t)
			gs.Expect(ss.GetClaim(tt.claim)).To(Equal(tt.want))
		})
	}
}
