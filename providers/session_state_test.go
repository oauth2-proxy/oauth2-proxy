package providers

import (
	"fmt"
	"testing"
	"time"

	"github.com/pusher/oauth2_proxy/cookie"
	"github.com/stretchr/testify/assert"
)

const secret = "0123456789abcdefghijklmnopqrstuv"
const altSecret = "0000000000abcdefghijklmnopqrstuv"

func TestSessionStateSerialization(t *testing.T) {
	c, err := cookie.NewCipher([]byte(secret))
	assert.Equal(t, nil, err)
	c2, err := cookie.NewCipher([]byte(altSecret))
	assert.Equal(t, nil, err)
	s := &SessionState{
		Email:        "user@domain.com",
		AccessToken:  "token1234",
		IDToken:      "rawtoken1234",
		ExpiresOn:    time.Now().Add(time.Duration(1) * time.Hour),
		RefreshToken: "refresh4321",
	}
	encoded, err := s.EncodeSessionState(c)
	assert.Equal(t, nil, err)

	ss, err := DecodeSessionState(encoded, c)
	t.Logf("%#v", ss)
	assert.Equal(t, nil, err)
	assert.Equal(t, "user@domain.com", ss.User)
	assert.Equal(t, s.Email, ss.Email)
	assert.Equal(t, s.AccessToken, ss.AccessToken)
	assert.Equal(t, s.IDToken, ss.IDToken)
	assert.Equal(t, s.ExpiresOn.Unix(), ss.ExpiresOn.Unix())
	assert.Equal(t, s.RefreshToken, ss.RefreshToken)

	// ensure a different cipher can't decode properly (ie: it gets gibberish)
	ss, err = DecodeSessionState(encoded, c2)
	t.Logf("%#v", ss)
	assert.Equal(t, nil, err)
	assert.NotEqual(t, "user@domain.com", ss.User)
	assert.NotEqual(t, s.Email, ss.Email)
	assert.Equal(t, s.ExpiresOn.Unix(), ss.ExpiresOn.Unix())
	assert.NotEqual(t, s.AccessToken, ss.AccessToken)
	assert.NotEqual(t, s.IDToken, ss.IDToken)
	assert.NotEqual(t, s.RefreshToken, ss.RefreshToken)
}

func TestSessionStateSerializationWithUser(t *testing.T) {
	c, err := cookie.NewCipher([]byte(secret))
	assert.Equal(t, nil, err)
	c2, err := cookie.NewCipher([]byte(altSecret))
	assert.Equal(t, nil, err)
	s := &SessionState{
		User:         "just-user",
		Email:        "user@domain.com",
		AccessToken:  "token1234",
		ExpiresOn:    time.Now().Add(time.Duration(1) * time.Hour),
		RefreshToken: "refresh4321",
	}
	encoded, err := s.EncodeSessionState(c)
	assert.Equal(t, nil, err)

	ss, err := DecodeSessionState(encoded, c)
	t.Logf("%#v", ss)
	assert.Equal(t, nil, err)
	assert.Equal(t, s.User, ss.User)
	assert.Equal(t, s.Email, ss.Email)
	assert.Equal(t, s.AccessToken, ss.AccessToken)
	assert.Equal(t, s.ExpiresOn.Unix(), ss.ExpiresOn.Unix())
	assert.Equal(t, s.RefreshToken, ss.RefreshToken)

	// ensure a different cipher can't decode properly (ie: it gets gibberish)
	ss, err = DecodeSessionState(encoded, c2)
	t.Logf("%#v", ss)
	assert.Equal(t, nil, err)
	assert.NotEqual(t, s.User, ss.User)
	assert.NotEqual(t, s.Email, ss.Email)
	assert.Equal(t, s.ExpiresOn.Unix(), ss.ExpiresOn.Unix())
	assert.NotEqual(t, s.AccessToken, ss.AccessToken)
	assert.NotEqual(t, s.RefreshToken, ss.RefreshToken)
}

func TestSessionStateSerializationNoCipher(t *testing.T) {
	s := &SessionState{
		Email:        "user@domain.com",
		AccessToken:  "token1234",
		ExpiresOn:    time.Now().Add(time.Duration(1) * time.Hour),
		RefreshToken: "refresh4321",
	}
	encoded, err := s.EncodeSessionState(nil)
	assert.Equal(t, nil, err)

	// only email should have been serialized
	ss, err := DecodeSessionState(encoded, nil)
	assert.Equal(t, nil, err)
	assert.Equal(t, "user@domain.com", ss.User)
	assert.Equal(t, s.Email, ss.Email)
	assert.Equal(t, "", ss.AccessToken)
	assert.Equal(t, "", ss.RefreshToken)
}

func TestSessionStateSerializationNoCipherWithUser(t *testing.T) {
	s := &SessionState{
		User:         "just-user",
		Email:        "user@domain.com",
		AccessToken:  "token1234",
		ExpiresOn:    time.Now().Add(time.Duration(1) * time.Hour),
		RefreshToken: "refresh4321",
	}
	encoded, err := s.EncodeSessionState(nil)
	assert.Equal(t, nil, err)

	// only email should have been serialized
	ss, err := DecodeSessionState(encoded, nil)
	assert.Equal(t, nil, err)
	assert.Equal(t, s.User, ss.User)
	assert.Equal(t, s.Email, ss.Email)
	assert.Equal(t, "", ss.AccessToken)
	assert.Equal(t, "", ss.RefreshToken)
}

func TestExpired(t *testing.T) {
	s := &SessionState{ExpiresOn: time.Now().Add(time.Duration(-1) * time.Minute)}
	assert.Equal(t, true, s.IsExpired())

	s = &SessionState{ExpiresOn: time.Now().Add(time.Duration(1) * time.Minute)}
	assert.Equal(t, false, s.IsExpired())

	s = &SessionState{}
	assert.Equal(t, false, s.IsExpired())
}

type testCase struct {
	SessionState
	Encoded string
	Cipher  *cookie.Cipher
	Error   bool
}

// TestEncodeSessionState tests EncodeSessionState with the test vector
//
// Currently only tests without cipher here because we have no way to mock
// the random generator used in EncodeSessionState.
func TestEncodeSessionState(t *testing.T) {
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
				ExpiresOn:    e,
				RefreshToken: "refresh4321",
			},
			Encoded: `{"Email":"user@domain.com","User":"just-user"}`,
		},
	}

	for i, tc := range testCases {
		encoded, err := tc.EncodeSessionState(tc.Cipher)
		t.Logf("i:%d Encoded:%#v SessionState:%#v Error:%#v", i, encoded, tc.SessionState, err)
		if tc.Error {
			assert.Error(t, err)
			assert.Empty(t, encoded)
			continue
		}
		assert.NoError(t, err)
		assert.JSONEq(t, tc.Encoded, encoded)
	}
}

// TestDecodeSessionState tests DecodeSessionState with the test vector
func TestDecodeSessionState(t *testing.T) {
	e := time.Now().Add(time.Duration(1) * time.Hour)
	eJSON, _ := e.MarshalJSON()
	eString := string(eJSON)
	eUnix := e.Unix()

	c, err := cookie.NewCipher([]byte(secret))
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
				User:  "user@domain.com",
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
			Encoded: fmt.Sprintf(`{"Email":"user@domain.com","User":"just-user","AccessToken":"I6s+ml+/MldBMgHIiC35BTKTh57skGX24w==","IDToken":"xojNdyyjB1HgYWh6XMtXY/Ph5eCVxa1cNsklJw==","RefreshToken":"qEX0x6RmASxo4dhlBG6YuRs9Syn/e9sHu/+K","ExpiresOn":%s}`, eString),
		},
		{
			SessionState: SessionState{
				Email:        "user@domain.com",
				User:         "just-user",
				AccessToken:  "token1234",
				IDToken:      "rawtoken1234",
				ExpiresOn:    e,
				RefreshToken: "refresh4321",
			},
			Encoded: fmt.Sprintf(`{"Email":"FsKKYrTWZWrxSOAqA/fTNAUZS5QWCqOBjuAbBlbVOw==","User":"rT6JP3dxQhxUhkWrrd7yt6c1mDVyQCVVxw==","AccessToken":"I6s+ml+/MldBMgHIiC35BTKTh57skGX24w==","IDToken":"xojNdyyjB1HgYWh6XMtXY/Ph5eCVxa1cNsklJw==","RefreshToken":"qEX0x6RmASxo4dhlBG6YuRs9Syn/e9sHu/+K","ExpiresOn":%s}`, eString),
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
			SessionState: SessionState{
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
			SessionState: SessionState{
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
		ss, err := DecodeSessionState(tc.Encoded, tc.Cipher)
		t.Logf("i:%d Encoded:%#v SessionState:%#v Error:%#v", i, tc.Encoded, ss, err)
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
