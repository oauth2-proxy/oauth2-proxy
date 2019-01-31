package providers

import (
	"encoding/base64"
	"fmt"
	"github.com/bitly/oauth2_proxy/cookie"
	"strconv"
	"strings"
	"time"
)

type SessionState struct {
	AccessToken  string
	IDToken      string
	ExpiresOn    time.Time
	RefreshToken string
	Email        string
	User         string
	ID           string
	Groups       string
}

func (s *SessionState) IsExpired() bool {
	if !s.ExpiresOn.IsZero() && s.ExpiresOn.Before(time.Now()) {
		return true
	}
	return false
}

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
	if s.Groups != "" {
		o += fmt.Sprintf(" groups:%s", s.Groups)
	}
	return o + "}"
}

func (s *SessionState) EncodeSessionState(c *cookie.Cipher) (string, error) {
	if c == nil || s.AccessToken == "" {
		return s.accountInfo(), nil
	}
	return s.EncryptedString(c)
}

func (s *SessionState) accountInfo() string {
	return fmt.Sprintf("email:%s user:%s id:%s", s.Email, s.User, s.ID)
}

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

	encoded_groups := base64.StdEncoding.EncodeToString([]byte(s.Groups))

	return fmt.Sprintf("%s|%s|%d|%s|%s", s.accountInfo(), a, s.ExpiresOn.Unix(), r, encoded_groups), nil
}

func decodeSessionStatePlain(v string) (s *SessionState, err error) {
	chunks := strings.Split(v, " ")
	if len(chunks) != 3 {
		return nil, fmt.Errorf("could not decode session state: expected 3 chunks got %d", len(chunks))
	}

	email := strings.TrimPrefix(chunks[0], "email:")
	user := strings.TrimPrefix(chunks[1], "user:")
	uid := strings.TrimPrefix(chunks[2], "id:")
	if user == "" {
		user = strings.Split(email, "@")[0]
	}

	return &SessionState{User: user, Email: email, ID: uid}, nil
}

func decodeUserGroups(v string) (groups string, err error) {
	decoded_groups, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return "", err
	}
	return string(decoded_groups), nil
}

func DecodeSessionState(v string, c *cookie.Cipher) (s *SessionState, err error) {
	if c == nil {
		return decodeSessionStatePlain(v)
	}

	chunks := strings.Split(v, "|")
	if len(chunks) != 5 {
		err = fmt.Errorf("invalid number of fields (got %d expected 5)", len(chunks))
		return
	}

	sessionState, err := decodeSessionStatePlain(chunks[0])
	if err != nil {
		return nil, err
	}

	// Access Token
	if chunks[1] != "" {
		if sessionState.AccessToken, err = c.Decrypt(chunks[1]); err != nil {
			return nil, err
		}
	}

	ts, _ := strconv.Atoi(chunks[2])
	sessionState.ExpiresOn = time.Unix(int64(ts), 0)

	// Refresh Token
	if chunks[3] != "" {
		if sessionState.RefreshToken, err = c.Decrypt(chunks[3]); err != nil {
			return nil, err
		}
	}

	// User groups
	if chunks[4] != "" {
		if sessionState.Groups, err = decodeUserGroups(chunks[4]); err != nil {
			return nil, err
		}
	}

	return sessionState, nil
}
