package sessions

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/encryption"
)

// SessionState is used to store information about the currently authenticated user session
type SessionState struct {
	AccessToken       string     `json:",omitempty"`
	IDToken           string     `json:",omitempty"`
	CreatedAt         *time.Time `json:",omitempty"`
	ExpiresOn         *time.Time `json:",omitempty"`
	RefreshToken      string     `json:",omitempty"`
	Email             string     `json:",omitempty"`
	User              string     `json:",omitempty"`
	PreferredUsername string     `json:",omitempty"`
}

// IsExpired checks whether the session has expired
func (s *SessionState) IsExpired() bool {
	if s.ExpiresOn != nil && !s.ExpiresOn.IsZero() && s.ExpiresOn.Before(time.Now()) {
		return true
	}
	return false
}

// Age returns the age of a session
func (s *SessionState) Age() time.Duration {
	if s.CreatedAt != nil && !s.CreatedAt.IsZero() {
		return time.Now().Truncate(time.Second).Sub(*s.CreatedAt)
	}
	return 0
}

// String constructs a summary of the session state
func (s *SessionState) String() string {
	o := fmt.Sprintf("Session{email:%s user:%s PreferredUsername:%s", s.Email, s.User, s.PreferredUsername)
	if s.AccessToken != "" {
		o += " token:true"
	}
	if s.IDToken != "" {
		o += " id_token:true"
	}
	if !s.CreatedAt.IsZero() {
		o += fmt.Sprintf(" created:%s", s.CreatedAt)
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
func (s *SessionState) EncodeSessionState(c encryption.Cipher) (string, error) {
	var ss SessionState
	if c == nil {
		// Store only Email and User when cipher is unavailable
		ss.Email = s.Email
		ss.User = s.User
		ss.PreferredUsername = s.PreferredUsername
	} else {
		ss = *s
		for _, s := range []*string{
			&ss.Email,
			&ss.User,
			&ss.PreferredUsername,
			&ss.AccessToken,
			&ss.IDToken,
			&ss.RefreshToken,
		} {
			err := into(s, c.Encrypt)
			if err != nil {
				return "", err
			}
		}
	}

	b, err := json.Marshal(ss)
	return string(b), err
}

// DecodeSessionState decodes the session cookie string into a SessionState
func DecodeSessionState(v string, c encryption.Cipher) (*SessionState, error) {
	var ss SessionState
	err := json.Unmarshal([]byte(v), &ss)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling session: %w", err)
	}

	if c == nil {
		// Load only Email and User when cipher is unavailable
		ss = SessionState{
			Email:             ss.Email,
			User:              ss.User,
			PreferredUsername: ss.PreferredUsername,
		}
	} else {
		// Backward compatibility with using unencrypted Email or User
		// Decryption errors will leave original string
		err = into(&ss.Email, c.Decrypt)
		if err == nil {
			if !utf8.ValidString(ss.Email) {
				return nil, errors.New("invalid value for decrypted email")
			}
		}
		err = into(&ss.User, c.Decrypt)
		if err == nil {
			if !utf8.ValidString(ss.User) {
				return nil, errors.New("invalid value for decrypted user")
			}
		}

		for _, s := range []*string{
			&ss.PreferredUsername,
			&ss.AccessToken,
			&ss.IDToken,
			&ss.RefreshToken,
		} {
			err := into(s, c.Decrypt)
			if err != nil {
				return nil, err
			}
		}
	}
	return &ss, nil
}

// codecFunc is a function that takes a []byte and encodes/decodes it
type codecFunc func([]byte) ([]byte, error)

func into(s *string, f codecFunc) error {
	// Do not encrypt/decrypt nil or empty strings
	if s == nil || *s == "" {
		return nil
	}

	d, err := f([]byte(*s))
	if err != nil {
		return err
	}
	*s = string(d)
	return nil
}
