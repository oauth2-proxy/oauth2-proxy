package sessions_test

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/encryption"
	"github.com/stretchr/testify/assert"
)

const secret = "0123456789abcdefghijklmnopqrstuv"
const altSecret = "0000000000abcdefghijklmnopqrstuv"

func TestSessionStateSerialization(t *testing.T) {
	c, err := encryption.NewCipher([]byte(secret))
	assert.Equal(t, nil, err)
	c2, err := encryption.NewCipher([]byte(altSecret))
	assert.Equal(t, nil, err)
	s := &sessions.SessionState{
		Email:             "user@domain.com",
		PreferredUsername: "user",
		AccessToken:       "token1234",
		IDToken:           "rawtoken1234",
		CreatedAt:         time.Now(),
		ExpiresOn:         time.Now().Add(time.Duration(1) * time.Hour),
		RefreshToken:      "refresh4321",
	}
	encoded, err := s.EncodeSessionState(c)
	assert.Equal(t, nil, err)

	ss, err := sessions.DecodeSessionState(encoded, c)
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
	ss, err = sessions.DecodeSessionState(encoded, c2)
	t.Logf("%#v", ss)
	assert.Equal(t, nil, err)
	assert.NotEqual(t, "user@domain.com", ss.User)
	assert.NotEqual(t, s.Email, ss.Email)
	assert.NotEqual(t, s.PreferredUsername, ss.PreferredUsername)
	assert.Equal(t, s.CreatedAt.Unix(), ss.CreatedAt.Unix())
	assert.Equal(t, s.ExpiresOn.Unix(), ss.ExpiresOn.Unix())
	assert.NotEqual(t, s.AccessToken, ss.AccessToken)
	assert.NotEqual(t, s.IDToken, ss.IDToken)
	assert.NotEqual(t, s.RefreshToken, ss.RefreshToken)
}

func TestSessionStateSerializationWithUser(t *testing.T) {
	c, err := encryption.NewCipher([]byte(secret))
	assert.Equal(t, nil, err)
	c2, err := encryption.NewCipher([]byte(altSecret))
	assert.Equal(t, nil, err)
	s := &sessions.SessionState{
		User:              "just-user",
		PreferredUsername: "ju",
		Email:             "user@domain.com",
		AccessToken:       "token1234",
		CreatedAt:         time.Now(),
		ExpiresOn:         time.Now().Add(time.Duration(1) * time.Hour),
		RefreshToken:      "refresh4321",
	}
	encoded, err := s.EncodeSessionState(c)
	assert.Equal(t, nil, err)

	ss, err := sessions.DecodeSessionState(encoded, c)
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
	ss, err = sessions.DecodeSessionState(encoded, c2)
	t.Logf("%#v", ss)
	assert.Equal(t, nil, err)
	assert.NotEqual(t, s.User, ss.User)
	assert.NotEqual(t, s.Email, ss.Email)
	assert.NotEqual(t, s.PreferredUsername, ss.PreferredUsername)
	assert.Equal(t, s.CreatedAt.Unix(), ss.CreatedAt.Unix())
	assert.Equal(t, s.ExpiresOn.Unix(), ss.ExpiresOn.Unix())
	assert.NotEqual(t, s.AccessToken, ss.AccessToken)
	assert.NotEqual(t, s.RefreshToken, ss.RefreshToken)
}

func TestSessionStateSerializationNoCipher(t *testing.T) {
	s := &sessions.SessionState{
		Email:             "user@domain.com",
		PreferredUsername: "user",
		AccessToken:       "token1234",
		CreatedAt:         time.Now(),
		ExpiresOn:         time.Now().Add(time.Duration(1) * time.Hour),
		RefreshToken:      "refresh4321",
	}
	encoded, err := s.EncodeSessionState(nil)
	assert.Equal(t, nil, err)

	// only email should have been serialized
	ss, err := sessions.DecodeSessionState(encoded, nil)
	assert.Equal(t, nil, err)
	assert.Equal(t, "", ss.User)
	assert.Equal(t, s.Email, ss.Email)
	assert.Equal(t, s.PreferredUsername, ss.PreferredUsername)
	assert.Equal(t, "", ss.AccessToken)
	assert.Equal(t, "", ss.RefreshToken)
}

func TestSessionStateSerializationNoCipherWithUser(t *testing.T) {
	s := &sessions.SessionState{
		User:              "just-user",
		Email:             "user@domain.com",
		PreferredUsername: "user",
		AccessToken:       "token1234",
		CreatedAt:         time.Now(),
		ExpiresOn:         time.Now().Add(time.Duration(1) * time.Hour),
		RefreshToken:      "refresh4321",
	}
	encoded, err := s.EncodeSessionState(nil)
	assert.Equal(t, nil, err)

	// only email should have been serialized
	ss, err := sessions.DecodeSessionState(encoded, nil)
	assert.Equal(t, nil, err)
	assert.Equal(t, s.User, ss.User)
	assert.Equal(t, s.Email, ss.Email)
	assert.Equal(t, s.PreferredUsername, ss.PreferredUsername)
	assert.Equal(t, "", ss.AccessToken)
	assert.Equal(t, "", ss.RefreshToken)
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

// TestEncodeSessionState tests EncodeSessionState with the test vector
//
// Currently only tests without cipher here because we have no way to mock
// the random generator used in EncodeSessionState.
func TestEncodeSessionState(t *testing.T) {
	c := time.Now()
	e := time.Now().Add(time.Duration(1) * time.Hour)

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
				Email:        "user@domain.com",
				User:         "just-user",
				AccessToken:  "token1234",
				IDToken:      "rawtoken1234",
				CreatedAt:    c,
				ExpiresOn:    e,
				RefreshToken: "refresh4321",
			},
			Encoded: `{"Email":"user@domain.com","User":"just-user"}`,
		},
	}

	for i, tc := range testCases {
		encoded, err := tc.EncodeSessionState(tc.Cipher)
		t.Logf("i:%d Encoded:%#vsessions.SessionState:%#v Error:%#v", i, encoded, tc.SessionState, err)
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
				User:  "",
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
	}

	for i, tc := range testCases {
		ss, err := sessions.DecodeSessionState(tc.Encoded, tc.Cipher)
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

func TestSessionCompressLargeStateSerializationCipher(t *testing.T) {

	rand.Seed(time.Now().UnixNano())

	c, err := encryption.NewCipher([]byte(secret))
	assert.Equal(t, nil, err)
	s := &sessions.SessionState{
		Email:             "user@domain.com",
		PreferredUsername: "user",
		AccessToken:       randStringRunes(1024 * 2),
		IDToken:           randStringRunes(1024 * 2),
		CreatedAt:         time.Now(),
		ExpiresOn:         time.Now().Add(time.Duration(1) * time.Hour),
		RefreshToken:      randStringRunes(1024 * 2),
		Compress:          false,
	}

	encodedUncompress, errUncompress := s.EncodeSessionState(c)
	assert.Equal(t, nil, errUncompress)

	s.Compress = true
	encoded, err := s.EncodeSessionState(c)
	assert.Equal(t, nil, err)

	t.Logf("Compare sizes compress %d and uncompress %d", len(encoded), len(encodedUncompress))

	ss, err := sessions.DecodeSessionState(encoded, c)
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
}

func TestSessionCompressLargeStateSerializationNoCipher(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	s := &sessions.SessionState{
		Email:             "user@domain.com",
		PreferredUsername: randStringRunes(1024),
		CreatedAt:         time.Now(),
		ExpiresOn:         time.Now().Add(time.Duration(1) * time.Hour),
		Compress:          false,
	}
	encodedUncompress, errUncompress := s.EncodeSessionState(nil)
	assert.Equal(t, nil, errUncompress)

	s.Compress = true
	encoded, err := s.EncodeSessionState(nil)
	assert.Equal(t, nil, err)

	t.Logf("Compare sizes compress %d and uncompress %d", len(encoded), len(encodedUncompress))

	// only email should have been serialized
	ss, err := sessions.DecodeSessionState(encoded, nil)
	t.Logf("%#v", ss)
	assert.Equal(t, nil, err)
	assert.Equal(t, s.User, ss.User)
	assert.Equal(t, s.Email, ss.Email)
	assert.Equal(t, s.PreferredUsername, ss.PreferredUsername)
	assert.Equal(t, "", ss.AccessToken)
	assert.Equal(t, "", ss.RefreshToken)
}

var letterRunes = []rune("abcdABCD")

func randStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
