package providers

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/pusher/oauth2_proxy/cookie"
)

// SessionState is used to store information about the currently authenticated user session
type SessionState struct {
	AccessToken  string    `json:",omitempty"`
	IDToken      string    `json:",omitempty"`
	ExpiresOn    time.Time `json:",omitempty"`
	RefreshToken string    `json:",omitempty"`
	Email        string    `json:",omitempty"`
	User         string    `json:",omitempty"`
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
	o := fmt.Sprintf("Session{email:%s user:%s", s.Email, s.User)
	if s.AccessToken != "" {
		o += " token:true"
	}
	if s.IDToken != "" {
		o += " id_token:true"
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
	ss := *s
	if c == nil {
		ss.AccessToken = ""
		ss.IDToken = ""
		ss.RefreshToken = ""
	} else {
		var err error
		ss.AccessToken, err = c.Encrypt(ss.AccessToken)
		if err != nil {
			return "", err
		}
		ss.IDToken, err = c.Encrypt(ss.IDToken)
		if err != nil {
			return "", err
		}
		ss.RefreshToken, err = c.Encrypt(ss.RefreshToken)
		if err != nil {
			return "", err
		}
	}
	b, err := json.Marshal(ss)
	return string(b), err
}

// DecodeSessionState decodes the session cookie string into a SessionState
func DecodeSessionState(v string, c *cookie.Cipher) (*SessionState, error) {
	ss := &SessionState{}
	err := json.Unmarshal([]byte(v), ss)
	if err != nil {
		return nil, err
	}
	if c != nil {
		ss.AccessToken, err = c.Decrypt(ss.AccessToken)
		if err != nil {
			return nil, err
		}
		ss.IDToken, err = c.Decrypt(ss.IDToken)
		if err != nil {
			return nil, err
		}
		ss.RefreshToken, err = c.Decrypt(ss.RefreshToken)
		if err != nil {
			return nil, err
		}
	}
	if ss.User == "" {
		ss.User = strings.Split(ss.Email, "@")[0]
	}
	return ss, nil
}
