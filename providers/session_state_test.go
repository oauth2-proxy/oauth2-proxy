package providers

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/bitly/oauth2_proxy/cookie"
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
		ExpiresOn:    time.Now().Add(time.Duration(1) * time.Hour),
		RefreshToken: "refresh4321",
	}
	encoded, err := s.EncodeSessionState(c)
	assert.Equal(t, nil, err)
	assert.Equal(t, 3, strings.Count(encoded, "|"))

	ss, err := DecodeSessionState(encoded, c)
	t.Logf("%#v", ss)
	assert.Equal(t, nil, err)
	assert.Equal(t, "user", ss.User)
	assert.Equal(t, s.Email, ss.Email)
	assert.Equal(t, s.AccessToken, ss.AccessToken)
	assert.Equal(t, s.ExpiresOn.Unix(), ss.ExpiresOn.Unix())
	assert.Equal(t, s.RefreshToken, ss.RefreshToken)

	// ensure a different cipher can't decode properly (ie: it gets gibberish)
	ss, err = DecodeSessionState(encoded, c2)
	t.Logf("%#v", ss)
	assert.Equal(t, nil, err)
	assert.Equal(t, "user", ss.User)
	assert.Equal(t, s.Email, ss.Email)
	assert.Equal(t, s.ExpiresOn.Unix(), ss.ExpiresOn.Unix())
	assert.NotEqual(t, s.AccessToken, ss.AccessToken)
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
	assert.Equal(t, 3, strings.Count(encoded, "|"))

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
	assert.Equal(t, s.User, ss.User)
	assert.Equal(t, s.Email, ss.Email)
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
	expected := fmt.Sprintf("email:%s user:", s.Email)
	assert.Equal(t, expected, encoded)

	// only email should have been serialized
	ss, err := DecodeSessionState(encoded, nil)
	assert.Equal(t, nil, err)
	assert.Equal(t, "user", ss.User)
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
	expected := fmt.Sprintf("email:%s user:%s", s.Email, s.User)
	assert.Equal(t, expected, encoded)

	// only email should have been serialized
	ss, err := DecodeSessionState(encoded, nil)
	assert.Equal(t, nil, err)
	assert.Equal(t, s.User, ss.User)
	assert.Equal(t, s.Email, ss.Email)
	assert.Equal(t, "", ss.AccessToken)
	assert.Equal(t, "", ss.RefreshToken)
}

func TestSessionStateAccountInfo(t *testing.T) {
	s := &SessionState{
		Email: "user@domain.com",
		User:  "just-user",
	}
	expected := fmt.Sprintf("email:%v user:%v", s.Email, s.User)
	assert.Equal(t, expected, s.accountInfo())

	s.Email = ""
	expected = fmt.Sprintf("email:%v user:%v", s.Email, s.User)
	assert.Equal(t, expected, s.accountInfo())
}

func TestExpired(t *testing.T) {
	s := &SessionState{ExpiresOn: time.Now().Add(time.Duration(-1) * time.Minute)}
	assert.Equal(t, true, s.IsExpired())

	s = &SessionState{ExpiresOn: time.Now().Add(time.Duration(1) * time.Minute)}
	assert.Equal(t, false, s.IsExpired())

	s = &SessionState{}
	assert.Equal(t, false, s.IsExpired())
}
