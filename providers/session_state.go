package providers

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/pusher/oauth2_proxy/cookie"
)

// SessionState is used to store information about the currently authenticated user session
type SessionState struct {
	AccessToken  string
	ExpiresOn    time.Time
	RefreshToken string
	Email        string
	User         string
}

// IsExpired checks whether the session has expired
func (s *SessionState) IsExpired() bool {
	if !s.ExpiresOn.IsZero() && s.ExpiresOn.Before(time.Now()) {
		return true
	}
	return false
}

// String constructs a summary of the session state
func (s *SessionState) String() string {
	o := fmt.Sprintf("Session{%s", s.accountInfo())
	if s.AccessToken != "" {
		o += " token:true"
	}
	if !s.ExpiresOn.IsZero() {
		o += fmt.Sprintf(" expires:%s", s.ExpiresOn)
	}
	if s.RefreshToken != "" {
		o += " refresh_token:true"
	}
	return o + "}"
}

// EncodeSessionState returns string representation of the current session
func (s *SessionState) EncodeSessionState(c *cookie.Cipher) (string, error) {
	if c == nil || s.AccessToken == "" {
		return s.accountInfo(), nil
	}
	return s.EncryptedString(c)
}

func (s *SessionState) accountInfo() string {
	return fmt.Sprintf("email:%s user:%s", s.Email, s.User)
}

// EncryptedString encrypts the session state into a cookie string
func (s *SessionState) EncryptedString(c *cookie.Cipher) (string, error) {
	var err error
	if c == nil {
		panic("error. missing cipher")
	}
	a := s.AccessToken
	if a != "" {
		if a, err = c.Encrypt(a); err != nil {
			return "", err
		}
	}
	r := s.RefreshToken
	if r != "" {
		if r, err = c.Encrypt(r); err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("%s|%s|%d|%s", s.accountInfo(), a, s.ExpiresOn.Unix(), r), nil
}

func decodeSessionStatePlain(v string) (s *SessionState, err error) {
	chunks := strings.Split(v, " ")
	if len(chunks) != 2 {
		return nil, fmt.Errorf("could not decode session state: expected 2 chunks got %d", len(chunks))
	}

	email := strings.TrimPrefix(chunks[0], "email:")
	user := strings.TrimPrefix(chunks[1], "user:")
	if user == "" {
		user = strings.Split(email, "@")[0]
	}

	return &SessionState{User: user, Email: email}, nil
}

// DecodeSessionState decodes the session cookie string into a SessionState
func DecodeSessionState(v string, c *cookie.Cipher) (s *SessionState, err error) {
	if c == nil {
		return decodeSessionStatePlain(v)
	}

	chunks := strings.Split(v, "|")
	if len(chunks) != 4 {
		err = fmt.Errorf("invalid number of fields (got %d expected 4)", len(chunks))
		return
	}

	sessionState, err := decodeSessionStatePlain(chunks[0])
	if err != nil {
		return nil, err
	}

	if chunks[1] != "" {
		if sessionState.AccessToken, err = c.Decrypt(chunks[1]); err != nil {
			return nil, err
		}
	}

	ts, _ := strconv.Atoi(chunks[2])
	sessionState.ExpiresOn = time.Unix(int64(ts), 0)

	if chunks[3] != "" {
		if sessionState.RefreshToken, err = c.Decrypt(chunks[3]); err != nil {
			return nil, err
		}
	}

	return sessionState, nil
}
