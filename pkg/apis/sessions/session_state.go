package sessions

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/encryption"
)

// SessionState is used to store information about the currently authenticated user session
type SessionState struct {
	AccessToken       string    `json:",omitempty"`
	IDToken           string    `json:",omitempty"`
	CreatedAt         time.Time `json:"-"`
	ExpiresOn         time.Time `json:"-"`
	RefreshToken      string    `json:",omitempty"`
	Email             string    `json:",omitempty"`
	User              string    `json:",omitempty"`
	PreferredUsername string    `json:",omitempty"`
	Compress          bool      `json:",omitempty"`
}

// SessionStateJSON is used to encode SessionState into JSON without exposing time.Time zero value
type SessionStateJSON struct {
	*SessionState
	CreatedAt *time.Time `json:",omitempty"`
	ExpiresOn *time.Time `json:",omitempty"`
}

const (
	minBytesToCompress = 256
)

// IsExpired checks whether the session has expired
func (s *SessionState) IsExpired() bool {
	if !s.ExpiresOn.IsZero() && s.ExpiresOn.Before(time.Now()) {
		return true
	}
	return false
}

// Age returns the age of a session
func (s *SessionState) Age() time.Duration {
	if !s.CreatedAt.IsZero() {
		return time.Now().Truncate(time.Second).Sub(s.CreatedAt)
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
func (s *SessionState) EncodeSessionState(c *encryption.Cipher) (string, error) {
	var ss SessionState
	if c == nil {
		// Store only Email and User when cipher is unavailable
		ss.Email = s.Email
		ss.User = s.User
		ss.PreferredUsername = s.PreferredUsername
	} else {
		ss = *s
		var err error
		if ss.Email != "" {
			ss.Email, err = c.Encrypt(ss.Email)
			if err != nil {
				return "", err
			}
		}
		if ss.User != "" {
			ss.User, err = c.Encrypt(ss.User)
			if err != nil {
				return "", err
			}
		}
		if ss.PreferredUsername != "" {
			ss.PreferredUsername, err = c.Encrypt(ss.PreferredUsername)
			if err != nil {
				return "", err
			}
		}
		if ss.AccessToken != "" {
			ss.AccessToken, err = c.Encrypt(ss.AccessToken)
			if err != nil {
				return "", err
			}
		}
		if ss.IDToken != "" {
			ss.IDToken, err = c.Encrypt(ss.IDToken)
			if err != nil {
				return "", err
			}
		}
		if ss.RefreshToken != "" {
			ss.RefreshToken, err = c.Encrypt(ss.RefreshToken)
			if err != nil {
				return "", err
			}
		}
	}
	// Embed SessionState and ExpiresOn pointer into SessionStateJSON
	ssj := &SessionStateJSON{SessionState: &ss}
	if !ss.CreatedAt.IsZero() {
		ssj.CreatedAt = &ss.CreatedAt
	}
	if !ss.ExpiresOn.IsZero() {
		ssj.ExpiresOn = &ss.ExpiresOn
	}
	b, err := json.Marshal(ssj)
	if !s.Compress || len(b) < minBytesToCompress || err != nil {
		return string(b), err
	}
	return compressToString(b), err
}

// DecodeSessionState decodes the session cookie string into a SessionState
func DecodeSessionState(v string, c *encryption.Cipher) (*SessionState, error) {

	jsonBody, err := uncompressStringToBytes(v)
	if err != nil {
		return nil, fmt.Errorf("error uncompress session: %w", err)
	}

	var ssj SessionStateJSON
	var ss *SessionState
	err = json.Unmarshal(jsonBody, &ssj)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling session: %w", err)
	}
	if ssj.SessionState == nil {
		return nil, errors.New("expected session state to not be nil")
	}

	// Extract SessionState and CreatedAt,ExpiresOn value from SessionStateJSON
	ss = ssj.SessionState
	if ssj.CreatedAt != nil {
		ss.CreatedAt = *ssj.CreatedAt
	}
	if ssj.ExpiresOn != nil {
		ss.ExpiresOn = *ssj.ExpiresOn
	}

	if c == nil {
		// Load only Email and User when cipher is unavailable
		ss = &SessionState{
			Email:             ss.Email,
			User:              ss.User,
			PreferredUsername: ss.PreferredUsername,
		}
	} else {
		// Backward compatibility with using unencrypted Email
		if ss.Email != "" {
			decryptedEmail, errEmail := c.Decrypt(ss.Email)
			if errEmail == nil {
				ss.Email = decryptedEmail
			}
		}
		// Backward compatibility with using unencrypted User
		if ss.User != "" {
			decryptedUser, errUser := c.Decrypt(ss.User)
			if errUser == nil {
				ss.User = decryptedUser
			}
		}
		if ss.PreferredUsername != "" {
			ss.PreferredUsername, err = c.Decrypt(ss.PreferredUsername)
			if err != nil {
				return nil, err
			}
		}
		if ss.AccessToken != "" {
			ss.AccessToken, err = c.Decrypt(ss.AccessToken)
			if err != nil {
				return nil, err
			}
		}
		if ss.IDToken != "" {
			ss.IDToken, err = c.Decrypt(ss.IDToken)
			if err != nil {
				return nil, err
			}
		}
		if ss.RefreshToken != "" {
			ss.RefreshToken, err = c.Decrypt(ss.RefreshToken)
			if err != nil {
				return nil, err
			}
		}
	}
	return ss, nil
}

func compress(v []byte) *bytes.Buffer {
	buf := &bytes.Buffer{}
	w, _ := gzip.NewWriterLevel(buf, gzip.BestSpeed)
	w.Write(v)
	w.Close()
	return buf
}

func compressToString(v []byte) string {
	return compress(v).String()
}

func uncompressStringToBytes(v string) ([]byte, error) {
	var b bytes.Buffer
	r, err := gzip.NewReader(strings.NewReader(v))
	if err != nil {
		if err == gzip.ErrHeader {
			return []byte(v), nil
		}
		return nil, err
	}
	_, err = io.Copy(&b, r)
	r.Close()
	return b.Bytes(), err
}
