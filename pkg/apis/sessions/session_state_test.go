package sessions_test

import (
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/encryption"
	"github.com/stretchr/testify/assert"
)

const secret = "0123456789abcdefghijklmnopqrstuv"
const altSecret = "0000000000abcdefghijklmnopqrstuv"

func TestSessionStateSerialization(t *testing.T) {
	s := &sessions.SessionState{
		Email:             "user@domain.com",
		PreferredUsername: "user",
		AccessToken:       "token1234",
		IDToken:           "rawtoken1234",
		CreatedAt:         time.Now(),
		ExpiresOn:         time.Now().Add(time.Duration(1) * time.Hour),
		RefreshToken:      "refresh4321",
	}
	encoded, err := s.EncodeSessionState(false, false)
	assert.Equal(t, nil, err)

	// No user results in a user auto-decoded and set from email
	ss, err := sessions.DecodeSessionState(encoded, false)
	t.Logf("%#v", ss)
	assert.Equal(t, nil, err)
	assert.Equal(t, "user@domain.com", ss.User)
	assert.Equal(t, s.Email, ss.Email)
	assert.Equal(t, s.PreferredUsername, ss.PreferredUsername)
	assert.Equal(t, s.AccessToken, ss.AccessToken)
	assert.Equal(t, s.IDToken, ss.IDToken)
	assert.Equal(t, s.CreatedAt.Unix(), ss.CreatedAt.Unix())
	assert.Equal(t, s.ExpiresOn.Unix(), ss.ExpiresOn.Unix())
	assert.Equal(t, s.RefreshToken, ss.RefreshToken)
}

func TestSessionStateSerializationMinimal(t *testing.T) {
	s := &sessions.SessionState{
		Email:             "user@domain.com",
		PreferredUsername: "user",
		AccessToken:       "token1234",
		IDToken:           "rawtoken1234",
		CreatedAt:         time.Now(),
		ExpiresOn:         time.Now().Add(time.Duration(1) * time.Hour),
		RefreshToken:      "refresh4321",
	}
	encoded, err := s.EncodeSessionState(false, true)
	assert.Equal(t, nil, err)

	// No user results in a user auto-decoded and set from email
	ss, err := sessions.DecodeSessionState(encoded, false)
	t.Logf("%#v", ss)
	assert.Equal(t, nil, err)
	assert.Equal(t, "user@domain.com", ss.User)
	assert.Equal(t, s.Email, ss.Email)
	assert.Equal(t, s.PreferredUsername, ss.PreferredUsername)
	assert.Equal(t, "", ss.AccessToken)
	assert.Equal(t, "", ss.IDToken)
	assert.Equal(t, s.CreatedAt.Unix(), ss.CreatedAt.Unix())
	assert.Equal(t, s.ExpiresOn.Unix(), ss.ExpiresOn.Unix())
	assert.Equal(t, "", ss.RefreshToken)
}

func TestSessionStateSerializationWithUser(t *testing.T) {
	s := &sessions.SessionState{
		User:              "just-user",
		PreferredUsername: "ju",
		Email:             "user@domain.com",
		AccessToken:       "token1234",
		CreatedAt:         time.Now(),
		ExpiresOn:         time.Now().Add(time.Duration(1) * time.Hour),
		RefreshToken:      "refresh4321",
	}
	encoded, err := s.EncodeSessionState(false, false)
	assert.Equal(t, nil, err)

	ss, err := sessions.DecodeSessionState(encoded, false)
	t.Logf("%#v", ss)
	assert.Equal(t, nil, err)
	assert.Equal(t, s.User, ss.User)
	assert.Equal(t, s.Email, ss.Email)
	assert.Equal(t, s.PreferredUsername, ss.PreferredUsername)
	assert.Equal(t, s.AccessToken, ss.AccessToken)
	assert.Equal(t, s.CreatedAt.Unix(), ss.CreatedAt.Unix())
	assert.Equal(t, s.ExpiresOn.Unix(), ss.ExpiresOn.Unix())
	assert.Equal(t, s.RefreshToken, ss.RefreshToken)
}

func TestSessionStateSerializationCompressed(t *testing.T) {
	s := &sessions.SessionState{
		Email:             "user@domain.com",
		PreferredUsername: "user",
		AccessToken:       "token1234",
		CreatedAt:         time.Now(),
		ExpiresOn:         time.Now().Add(time.Duration(1) * time.Hour),
		RefreshToken:      "refresh4321",
	}
	encoded, err := s.EncodeSessionState(true, false)
	assert.Equal(t, nil, err)

	// No user results in a user auto-decoded and set from email
	ss, err := sessions.DecodeSessionState(encoded, true)
	assert.Equal(t, nil, err)
	assert.Equal(t, "user@domain.com", ss.User)
	assert.Equal(t, s.Email, ss.Email)
	assert.Equal(t, s.PreferredUsername, ss.PreferredUsername)
	assert.Equal(t, s.AccessToken, ss.AccessToken)
	assert.Equal(t, s.RefreshToken, ss.RefreshToken)
}

func TestSessionStateSerializationCompressedWithUser(t *testing.T) {
	s := &sessions.SessionState{
		User:              "just-user",
		Email:             "user@domain.com",
		PreferredUsername: "user",
		AccessToken:       "token1234",
		CreatedAt:         time.Now(),
		ExpiresOn:         time.Now().Add(time.Duration(1) * time.Hour),
		RefreshToken:      "refresh4321",
	}
	encoded, err := s.EncodeSessionState(true, false)
	assert.Equal(t, nil, err)

	ss, err := sessions.DecodeSessionState(encoded, true)
	assert.Equal(t, nil, err)
	assert.Equal(t, s.User, ss.User)
	assert.Equal(t, s.Email, ss.Email)
	assert.Equal(t, s.PreferredUsername, ss.PreferredUsername)
	assert.Equal(t, s.AccessToken, ss.AccessToken)
	assert.Equal(t, s.RefreshToken, ss.RefreshToken)
}

func TestExpired(t *testing.T) {
	s := &sessions.SessionState{ExpiresOn: time.Now().Add(time.Duration(-1) * time.Minute)}
	assert.Equal(t, true, s.IsExpired())

	s = &sessions.SessionState{ExpiresOn: time.Now().Add(time.Duration(1) * time.Minute)}
	assert.Equal(t, false, s.IsExpired())

	s = &sessions.SessionState{}
	assert.Equal(t, false, s.IsExpired())
}

type testCase struct {
	sessions.SessionState
	Encoded string
	Cipher  *encryption.Cipher
	Error   bool
}

// TestDecodeSessionState tests sessions.LegacyV5DecodeSessionState with the test vector
func TestLegacyV5DecodeSessionState(t *testing.T) {
	created := time.Now()
	createdJSON, _ := created.MarshalJSON()
	createdString := string(createdJSON)
	e := time.Now().Add(time.Duration(1) * time.Hour)
	eJSON, _ := e.MarshalJSON()
	eString := string(eJSON)
	eUnix := e.Unix()

	c, err := encryption.NewCipher([]byte(secret))
	assert.NoError(t, err)

	testCases := []testCase{
		{
			SessionState: sessions.SessionState{
				Email: "user@domain.com",
				User:  "just-user",
			},
			Encoded: `{"Email":"user@domain.com","User":"just-user"}`,
		},
		{
			SessionState: sessions.SessionState{
				Email: "user@domain.com",
				User:  "user@domain.com",
			},
			Encoded: `{"Email":"user@domain.com"}`,
		},
		{
			SessionState: sessions.SessionState{
				User: "just-user",
			},
			Encoded: `{"User":"just-user"}`,
		},
		{
			SessionState: sessions.SessionState{
				Email: "user@domain.com",
				User:  "just-user",
			},
			Encoded: fmt.Sprintf(`{"Email":"user@domain.com","User":"just-user","AccessToken":"I6s+ml+/MldBMgHIiC35BTKTh57skGX24w==","IDToken":"xojNdyyjB1HgYWh6XMtXY/Ph5eCVxa1cNsklJw==","RefreshToken":"qEX0x6RmASxo4dhlBG6YuRs9Syn/e9sHu/+K","CreatedAt":%s,"ExpiresOn":%s}`, createdString, eString),
		},
		{
			SessionState: sessions.SessionState{
				Email:        "user@domain.com",
				User:         "just-user",
				AccessToken:  "token1234",
				IDToken:      "rawtoken1234",
				CreatedAt:    created,
				ExpiresOn:    e,
				RefreshToken: "refresh4321",
			},
			Encoded: fmt.Sprintf(`{"Email":"FsKKYrTWZWrxSOAqA/fTNAUZS5QWCqOBjuAbBlbVOw==","User":"rT6JP3dxQhxUhkWrrd7yt6c1mDVyQCVVxw==","AccessToken":"I6s+ml+/MldBMgHIiC35BTKTh57skGX24w==","IDToken":"xojNdyyjB1HgYWh6XMtXY/Ph5eCVxa1cNsklJw==","RefreshToken":"qEX0x6RmASxo4dhlBG6YuRs9Syn/e9sHu/+K","CreatedAt":%s,"ExpiresOn":%s}`, createdString, eString),
			Cipher:  c,
		},
		{
			SessionState: sessions.SessionState{
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
			SessionState: sessions.SessionState{
				User:  "just-user",
				Email: "user@domain.com",
			},
			Encoded: "email:user@domain.com user:just-user",
		},
		{
			Encoded: "email:user@domain.com user:just-user||||",
			Error:   true,
		},
		{
			Encoded: "email:user@domain.com user:just-user",
			Cipher:  c,
			Error:   true,
		},
		{
			Encoded: "email:user@domain.com user:just-user|||99999999999999999999|",
			Cipher:  c,
			Error:   true,
		},
		{
			SessionState: sessions.SessionState{
				Email:        "user@domain.com",
				User:         "just-user",
				AccessToken:  "token1234",
				ExpiresOn:    e,
				RefreshToken: "refresh4321",
			},
			Encoded: fmt.Sprintf("email:user@domain.com user:just-user|I6s+ml+/MldBMgHIiC35BTKTh57skGX24w==|%d|qEX0x6RmASxo4dhlBG6YuRs9Syn/e9sHu/+K", eUnix),
			Cipher:  c,
		},
		{
			SessionState: sessions.SessionState{
				Email:        "user@domain.com",
				User:         "just-user",
				AccessToken:  "token1234",
				IDToken:      "rawtoken1234",
				ExpiresOn:    e,
				RefreshToken: "refresh4321",
			},
			Encoded: fmt.Sprintf("email:user@domain.com user:just-user|I6s+ml+/MldBMgHIiC35BTKTh57skGX24w==|xojNdyyjB1HgYWh6XMtXY/Ph5eCVxa1cNsklJw==|%d|qEX0x6RmASxo4dhlBG6YuRs9Syn/e9sHu/+K", eUnix),
			Cipher:  c,
		},
	}

	for i, tc := range testCases {
		ss, err := sessions.LegacyV5DecodeSessionState(tc.Encoded, tc.Cipher)
		t.Logf("i:%d Encoded:%#vsessions.SessionState:%#v Error:%#v", i, tc.Encoded, ss, err)
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
			assert.Equal(t, tc.ExpiresOn.Unix(), ss.ExpiresOn.Unix())
		}
	}
}

func TestSessionStateAge(t *testing.T) {
	ss := &sessions.SessionState{}

	// Created at unset so should be 0
	assert.Equal(t, time.Duration(0), ss.Age())

	// Set CreatedAt to 1 hour ago
	ss.CreatedAt = time.Now().Add(-1 * time.Hour)
	assert.Equal(t, time.Hour, ss.Age().Round(time.Minute))
}

func TestEncodeAndDecodeSessionState(t *testing.T) {
	created := time.Now()
	expires := time.Now().Add(time.Duration(1) * time.Hour)

	testCases := []testCase{
		{
			SessionState: sessions.SessionState{
				Email: "user@domain.com",
				User:  "just-user",
			},
		},
		{
			SessionState: sessions.SessionState{
				Email: "user@domain.com",
				User:  "user@domain.com",
			},
		},
		{
			SessionState: sessions.SessionState{
				User: "just-user",
			},
		},
		{
			SessionState: sessions.SessionState{
				Email:             "user@domain.com",
				User:              "just-user",
				PreferredUsername: "preferred",
			},
		},
		{
			SessionState: sessions.SessionState{
				Email:             "user@domain.com",
				User:              "just-user",
				PreferredUsername: "preferred",
				AccessToken:       base64.URLEncoding.EncodeToString([]byte("token1234")),
				IDToken:           base64.URLEncoding.EncodeToString([]byte("idtoken1234")),
				CreatedAt:         created,
				ExpiresOn:         expires,
				RefreshToken:      base64.URLEncoding.EncodeToString([]byte("refresh4321")),
			},
		},
		{
			SessionState: sessions.SessionState{
				Email:             "user@domain.com",
				User:              "just-user",
				PreferredUsername: "preferred",
				AccessToken:       base64.URLEncoding.EncodeToString([]byte("token1234")),
				IDToken:           "rawtoken1234",
				CreatedAt:         created,
				ExpiresOn:         expires,
				RefreshToken:      base64.URLEncoding.EncodeToString([]byte("refresh4321")),
			},
		},
		{
			SessionState: sessions.SessionState{
				Email:             "user@domain.com",
				User:              "just-user",
				PreferredUsername: "preferred",
				AccessToken:       "token1234",
				IDToken:           "idtoken1234",
				CreatedAt:         created,
				ExpiresOn:         expires,
				RefreshToken:      "refresh4321",
			},
		},
		{
			SessionState: sessions.SessionState{
				Email:        "user@domain.com",
				User:         "just-user",
				AccessToken:  base64.URLEncoding.EncodeToString([]byte("token1234")),
				ExpiresOn:    expires,
				RefreshToken: base64.URLEncoding.EncodeToString([]byte("refresh4321")),
			},
		},
		{
			SessionState: sessions.SessionState{
				Email:        "user@domain.com",
				User:         "just-user",
				AccessToken:  base64.URLEncoding.EncodeToString([]byte("token1234")),
				IDToken:      base64.URLEncoding.EncodeToString([]byte("idtoken1234")),
				ExpiresOn:    expires,
				RefreshToken: base64.URLEncoding.EncodeToString([]byte("refresh4321")),
			},
		},
	}

	// Without Compression
	for _, tc := range testCases {
		data, err := tc.EncodeSessionState(false, false)
		assert.NoError(t, err)
		ss, err := sessions.DecodeSessionState(data, false)
		assert.NoError(t, err)
		if assert.NotNil(t, ss) {
			assert.Equal(t, tc.User, ss.User)
			assert.Equal(t, tc.PreferredUsername, ss.PreferredUsername)
			assert.Equal(t, tc.Email, ss.Email)
			assert.Equal(t, tc.AccessToken, ss.AccessToken)
			assert.Equal(t, tc.RefreshToken, ss.RefreshToken)
			assert.Equal(t, tc.IDToken, ss.IDToken)
			assert.Equal(t, tc.CreatedAt.Unix(), ss.CreatedAt.Unix())
			assert.Equal(t, tc.ExpiresOn.Unix(), ss.ExpiresOn.Unix())
		}
	}

	// Minimal
	for _, tc := range testCases {
		data, err := tc.EncodeSessionState(false, true)
		assert.NoError(t, err)
		ss, err := sessions.DecodeSessionState(data, false)
		assert.NoError(t, err)
		if assert.NotNil(t, ss) {
			assert.Equal(t, tc.User, ss.User)
			assert.Equal(t, tc.PreferredUsername, ss.PreferredUsername)
			assert.Equal(t, tc.Email, ss.Email)
			assert.Equal(t, "", ss.AccessToken)
			assert.Equal(t, "", ss.RefreshToken)
			assert.Equal(t, "", ss.IDToken)
			assert.Equal(t, tc.CreatedAt.Unix(), ss.CreatedAt.Unix())
			assert.Equal(t, tc.ExpiresOn.Unix(), ss.ExpiresOn.Unix())
		}
	}

	// With Compression
	for _, tc := range testCases {
		data, err := tc.EncodeSessionState(false, false)
		assert.NoError(t, err)
		ss, err := sessions.DecodeSessionState(data, false)
		assert.NoError(t, err)
		if assert.NotNil(t, ss) {
			assert.Equal(t, tc.User, ss.User)
			assert.Equal(t, tc.PreferredUsername, ss.PreferredUsername)
			assert.Equal(t, tc.Email, ss.Email)
			assert.Equal(t, tc.AccessToken, ss.AccessToken)
			assert.Equal(t, tc.RefreshToken, ss.RefreshToken)
			assert.Equal(t, tc.IDToken, ss.IDToken)
			assert.Equal(t, tc.CreatedAt.Unix(), ss.CreatedAt.Unix())
			assert.Equal(t, tc.ExpiresOn.Unix(), ss.ExpiresOn.Unix())
		}
	}
}

// Confirm legacy JSON cookies passed into DecodeSessionState throw errors
func TestDecodeSessionStateBadData(t *testing.T) {
	created := time.Now()
	createdJSON, _ := created.MarshalJSON()
	createdString := string(createdJSON)
	e := time.Now().Add(time.Duration(1) * time.Hour)
	eJSON, _ := e.MarshalJSON()
	eString := string(eJSON)
	eUnix := e.Unix()

	testCases := []testCase{
		{
			Encoded: `{"Email":"user@domain.com","User":"just-user"}`,
		},
		{
			Encoded: `{"Email":"user@domain.com"}`,
		},
		{
			Encoded: `{"User":"just-user"}`,
		},
		{
			Encoded: fmt.Sprintf(`{"Email":"user@domain.com","User":"just-user","AccessToken":"I6s+ml+/MldBMgHIiC35BTKTh57skGX24w==","IDToken":"xojNdyyjB1HgYWh6XMtXY/Ph5eCVxa1cNsklJw==","RefreshToken":"qEX0x6RmASxo4dhlBG6YuRs9Syn/e9sHu/+K","CreatedAt":%s,"ExpiresOn":%s}`, createdString, eString),
		},
		{
			Encoded: fmt.Sprintf(`{"Email":"FsKKYrTWZWrxSOAqA/fTNAUZS5QWCqOBjuAbBlbVOw==","User":"rT6JP3dxQhxUhkWrrd7yt6c1mDVyQCVVxw==","AccessToken":"I6s+ml+/MldBMgHIiC35BTKTh57skGX24w==","IDToken":"xojNdyyjB1HgYWh6XMtXY/Ph5eCVxa1cNsklJw==","RefreshToken":"qEX0x6RmASxo4dhlBG6YuRs9Syn/e9sHu/+K","CreatedAt":%s,"ExpiresOn":%s}`, createdString, eString),
		},
		{
			Encoded: `{"Email":"EGTllJcOFC16b7LBYzLekaHAC5SMMSPdyUrg8hd25g==","User":"rT6JP3dxQhxUhkWrrd7yt6c1mDVyQCVVxw=="}`,
		},
		{
			Encoded: `{"Email":"user@domain.com","User":"just-user","AccessToken":"X"}`,
		},
		{
			Encoded: `{"Email":"user@domain.com","User":"just-user","IDToken":"XXXX"}`,
		},
		{
			Encoded: "email:user@domain.com user:just-user",
		},
		{
			Encoded: "email:user@domain.com user:just-user||||",
		},
		{
			Encoded: "email:user@domain.com user:just-user",
		},
		{
			Encoded: "email:user@domain.com user:just-user|||99999999999999999999|",
		},
		{
			Encoded: fmt.Sprintf("email:user@domain.com user:just-user|I6s+ml+/MldBMgHIiC35BTKTh57skGX24w==|%d|qEX0x6RmASxo4dhlBG6YuRs9Syn/e9sHu/+K", eUnix),
		},
		{
			Encoded: fmt.Sprintf("email:user@domain.com user:just-user|I6s+ml+/MldBMgHIiC35BTKTh57skGX24w==|xojNdyyjB1HgYWh6XMtXY/Ph5eCVxa1cNsklJw==|%d|qEX0x6RmASxo4dhlBG6YuRs9Syn/e9sHu/+K", eUnix),
		},
	}

	// If uncompressed data sneaks in (ie Legacy Sessions), this should fail
	var err error
	for _, tc := range testCases {
		_, err = sessions.DecodeSessionState([]byte(tc.Encoded), false)
		assert.Error(t, err)
	}
	for _, tc := range testCases {
		_, err = sessions.DecodeSessionState([]byte(tc.Encoded), true)
		assert.Error(t, err)
	}
}
