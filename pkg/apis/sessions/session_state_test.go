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
const altSecret = "0000000000abcdefghijklmnopqrstuv"

func timePtr(t time.Time) *time.Time {
	return &t
}

func newTestCipher(secret []byte) (encryption.Cipher, error) {
	return encryption.NewBase64Cipher(encryption.NewCFBCipher, secret)
}

func TestSessionStateSerialization(t *testing.T) {
	c, err := newTestCipher([]byte(secret))
	assert.Equal(t, nil, err)
	c2, err := newTestCipher([]byte(altSecret))
	assert.Equal(t, nil, err)
	s := &SessionState{
		Email:             "user@domain.com",
		PreferredUsername: "user",
		AccessToken:       "token1234",
		IDToken:           "rawtoken1234",
		CreatedAt:         timePtr(time.Now()),
		ExpiresOn:         timePtr(time.Now().Add(time.Duration(1) * time.Hour)),
		RefreshToken:      "refresh4321",
	}
	encoded, err := s.EncodeSessionState(c)
	assert.Equal(t, nil, err)

	ss, err := DecodeSessionState(encoded, c)
	t.Logf("%#v", ss)
	assert.Equal(t, nil, err)
	assert.Equal(t, "", ss.User)
	assert.Equal(t, s.Email, ss.Email)
	assert.Equal(t, s.PreferredUsername, ss.PreferredUsername)
	assert.Equal(t, s.AccessToken, ss.AccessToken)
	assert.Equal(t, s.IDToken, ss.IDToken)
	assert.Equal(t, s.CreatedAt.Unix(), ss.CreatedAt.Unix())
	assert.Equal(t, s.ExpiresOn.Unix(), ss.ExpiresOn.Unix())
	assert.Equal(t, s.RefreshToken, ss.RefreshToken)

	// ensure a different cipher can't decode properly (ie: it gets gibberish)
	ss, err = DecodeSessionState(encoded, c2)
	t.Logf("%#v", ss)
	assert.NotEqual(t, nil, err)
}

func TestSessionStateSerializationWithUser(t *testing.T) {
	c, err := newTestCipher([]byte(secret))
	assert.Equal(t, nil, err)
	c2, err := newTestCipher([]byte(altSecret))
	assert.Equal(t, nil, err)
	s := &SessionState{
		User:              "just-user",
		PreferredUsername: "ju",
		Email:             "user@domain.com",
		AccessToken:       "token1234",
		CreatedAt:         timePtr(time.Now()),
		ExpiresOn:         timePtr(time.Now().Add(time.Duration(1) * time.Hour)),
		RefreshToken:      "refresh4321",
	}
	encoded, err := s.EncodeSessionState(c)
	assert.Equal(t, nil, err)

	ss, err := DecodeSessionState(encoded, c)
	t.Logf("%#v", ss)
	assert.Equal(t, nil, err)
	assert.Equal(t, s.User, ss.User)
	assert.Equal(t, s.Email, ss.Email)
	assert.Equal(t, s.PreferredUsername, ss.PreferredUsername)
	assert.Equal(t, s.AccessToken, ss.AccessToken)
	assert.Equal(t, s.CreatedAt.Unix(), ss.CreatedAt.Unix())
	assert.Equal(t, s.ExpiresOn.Unix(), ss.ExpiresOn.Unix())
	assert.Equal(t, s.RefreshToken, ss.RefreshToken)

	// ensure a different cipher can't decode properly (ie: it gets gibberish)
	ss, err = DecodeSessionState(encoded, c2)
	t.Logf("%#v", ss)
	assert.NotEqual(t, nil, err)
}

func TestSessionStateSerializationNoCipher(t *testing.T) {
	s := &SessionState{
		Email:             "user@domain.com",
		PreferredUsername: "user",
		AccessToken:       "token1234",
		CreatedAt:         timePtr(time.Now()),
		ExpiresOn:         timePtr(time.Now().Add(time.Duration(1) * time.Hour)),
		RefreshToken:      "refresh4321",
	}
	encoded, err := s.EncodeSessionState(nil)
	assert.Equal(t, nil, err)

	// only email should have been serialized
	ss, err := DecodeSessionState(encoded, nil)
	assert.Equal(t, nil, err)
	assert.Equal(t, "", ss.User)
	assert.Equal(t, s.Email, ss.Email)
	assert.Equal(t, s.PreferredUsername, ss.PreferredUsername)
	assert.Equal(t, "", ss.AccessToken)
	assert.Equal(t, "", ss.RefreshToken)
}

func TestSessionStateSerializationNoCipherWithUser(t *testing.T) {
	s := &SessionState{
		User:              "just-user",
		Email:             "user@domain.com",
		PreferredUsername: "user",
		AccessToken:       "token1234",
		CreatedAt:         timePtr(time.Now()),
		ExpiresOn:         timePtr(time.Now().Add(time.Duration(1) * time.Hour)),
		RefreshToken:      "refresh4321",
	}
	encoded, err := s.EncodeSessionState(nil)
	assert.Equal(t, nil, err)

	// only email should have been serialized
	ss, err := DecodeSessionState(encoded, nil)
	assert.Equal(t, nil, err)
	assert.Equal(t, s.User, ss.User)
	assert.Equal(t, s.Email, ss.Email)
	assert.Equal(t, s.PreferredUsername, ss.PreferredUsername)
	assert.Equal(t, "", ss.AccessToken)
	assert.Equal(t, "", ss.RefreshToken)
}

func TestExpired(t *testing.T) {
	s := &SessionState{ExpiresOn: timePtr(time.Now().Add(time.Duration(-1) * time.Minute))}
	assert.Equal(t, true, s.IsExpired())

	s = &SessionState{ExpiresOn: timePtr(time.Now().Add(time.Duration(1) * time.Minute))}
	assert.Equal(t, false, s.IsExpired())

	s = &SessionState{}
	assert.Equal(t, false, s.IsExpired())
}

type testCase struct {
	SessionState
	Encoded string
	Cipher  encryption.Cipher
	Error   bool
}

// TestEncodeSessionState tests EncodeSessionState with the test vector
//
// Currently only tests without cipher here because we have no way to mock
// the random generator used in EncodeSessionState.
func TestEncodeSessionState(t *testing.T) {
	c := time.Now()
	e := time.Now().Add(time.Duration(1) * time.Hour)

	testCases := []testCase{
		{
			SessionState: SessionState{
				Email: "user@domain.com",
				User:  "just-user",
			},
			Encoded: `{"Email":"user@domain.com","User":"just-user"}`,
		},
		{
			SessionState: SessionState{
				Email:        "user@domain.com",
				User:         "just-user",
				AccessToken:  "token1234",
				IDToken:      "rawtoken1234",
				CreatedAt:    &c,
				ExpiresOn:    &e,
				RefreshToken: "refresh4321",
			},
			Encoded: `{"Email":"user@domain.com","User":"just-user"}`,
		},
	}

	for i, tc := range testCases {
		encoded, err := tc.EncodeSessionState(tc.Cipher)
		t.Logf("i:%d Encoded:%#vSessionState:%#v Error:%#v", i, encoded, tc.SessionState, err)
		if tc.Error {
			assert.Error(t, err)
			assert.Empty(t, encoded)
			continue
		}
		assert.NoError(t, err)
		assert.JSONEq(t, tc.Encoded, encoded)
	}
}

// TestDecodeSessionState testssessions.DecodeSessionState with the test vector
func TestDecodeSessionState(t *testing.T) {
	created := time.Now()
	createdJSON, _ := created.MarshalJSON()
	createdString := string(createdJSON)
	e := time.Now().Add(time.Duration(1) * time.Hour)
	eJSON, _ := e.MarshalJSON()
	eString := string(eJSON)

	c, err := newTestCipher([]byte(secret))
	assert.NoError(t, err)

	testCases := []testCase{
		{
			SessionState: SessionState{
				Email: "user@domain.com",
				User:  "just-user",
			},
			Encoded: `{"Email":"user@domain.com","User":"just-user"}`,
		},
		{
			SessionState: SessionState{
				Email: "user@domain.com",
				User:  "",
			},
			Encoded: `{"Email":"user@domain.com"}`,
		},
		{
			SessionState: SessionState{
				User: "just-user",
			},
			Encoded: `{"User":"just-user"}`,
		},
		{
			SessionState: SessionState{
				Email: "user@domain.com",
				User:  "just-user",
			},
			Encoded: fmt.Sprintf(`{"Email":"user@domain.com","User":"just-user","AccessToken":"I6s+ml+/MldBMgHIiC35BTKTh57skGX24w==","IDToken":"xojNdyyjB1HgYWh6XMtXY/Ph5eCVxa1cNsklJw==","RefreshToken":"qEX0x6RmASxo4dhlBG6YuRs9Syn/e9sHu/+K","CreatedAt":%s,"ExpiresOn":%s}`, createdString, eString),
		},
		{
			SessionState: SessionState{
				Email:        "user@domain.com",
				User:         "just-user",
				AccessToken:  "token1234",
				IDToken:      "rawtoken1234",
				CreatedAt:    &created,
				ExpiresOn:    &e,
				RefreshToken: "refresh4321",
			},
			Encoded: fmt.Sprintf(`{"Email":"FsKKYrTWZWrxSOAqA/fTNAUZS5QWCqOBjuAbBlbVOw==","User":"rT6JP3dxQhxUhkWrrd7yt6c1mDVyQCVVxw==","AccessToken":"I6s+ml+/MldBMgHIiC35BTKTh57skGX24w==","IDToken":"xojNdyyjB1HgYWh6XMtXY/Ph5eCVxa1cNsklJw==","RefreshToken":"qEX0x6RmASxo4dhlBG6YuRs9Syn/e9sHu/+K","CreatedAt":%s,"ExpiresOn":%s}`, createdString, eString),
			Cipher:  c,
		},
		{
			SessionState: SessionState{
				Email: "user@domain.com",
				User:  "just-user",
			},
			Encoded: `{"Email":"EGTllJcOFC16b7LBYzLekaHAC5SMMSPdyUrg8hd25g==","User":"rT6JP3dxQhxUhkWrrd7yt6c1mDVyQCVVxw=="}`,
			Cipher:  c,
		},
		{
			Encoded: `{"Email":"user@domain.com","User":"just-user","AccessToken":"X"}`,
			Cipher:  c,
			Error:   true,
		},
		{
			Encoded: `{"Email":"user@domain.com","User":"just-user","IDToken":"XXXX"}`,
			Cipher:  c,
			Error:   true,
		},
		{
			SessionState: SessionState{
				Email: "user@domain.com",
				User:  "YmFzZTY0LWVuY29kZWQtdXNlcgo=", // Base64 encoding of base64-encoded-user
			},
			Error:  true,
			Cipher: c,
		},
	}

	for i, tc := range testCases {
		ss, err := DecodeSessionState(tc.Encoded, tc.Cipher)
		t.Logf("i:%d Encoded:%#vSessionState:%#v Error:%#v", i, tc.Encoded, ss, err)
		if tc.Error {
			assert.Error(t, err)
			assert.Nil(t, ss)
			continue
		}
		assert.NoError(t, err)
		if assert.NotNil(t, ss) {
			assert.Equal(t, tc.User, ss.User)
			assert.Equal(t, tc.Email, ss.Email)
			assert.Equal(t, tc.AccessToken, ss.AccessToken)
			assert.Equal(t, tc.RefreshToken, ss.RefreshToken)
			assert.Equal(t, tc.IDToken, ss.IDToken)
			if tc.ExpiresOn != nil {
				assert.NotEqual(t, nil, ss.ExpiresOn)
				assert.Equal(t, tc.ExpiresOn.Unix(), ss.ExpiresOn.Unix())
			}
		}
	}
}

func TestSessionStateAge(t *testing.T) {
	ss := &SessionState{}

	// Created at unset so should be 0
	assert.Equal(t, time.Duration(0), ss.Age())

	// Set CreatedAt to 1 hour ago
	ss.CreatedAt = timePtr(time.Now().Add(-1 * time.Hour))
	assert.Equal(t, time.Hour, ss.Age().Round(time.Minute))
}

func TestIntoEncryptAndIntoDecrypt(t *testing.T) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// Test all 3 valid AES sizes
	for _, secretSize := range []int{16, 24, 32} {
		t.Run(fmt.Sprintf("%d", secretSize), func(t *testing.T) {
			secret := make([]byte, secretSize)
			_, err := io.ReadFull(rand.Reader, secret)
			assert.Equal(t, nil, err)

			c, err := newTestCipher(secret)
			assert.NoError(t, err)

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
