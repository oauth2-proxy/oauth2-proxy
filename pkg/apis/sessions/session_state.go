package sessions

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/coreos/go-oidc"
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

	// Internal parts used to transfer data between provider
	// and the main Oauthproxy paths. Not meant to be serialized.
	rawClaims      map[string]interface{}
	rawClaimsValid bool
}

// SessionStateJSON is used to encode SessionState into JSON without exposing time.Time zero value
type SessionStateJSON struct {
	*SessionState
	CreatedAt *time.Time `json:",omitempty"`
	ExpiresOn *time.Time `json:",omitempty"`
}

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
	return string(b), err
}

// DecodeSessionState decodes the session cookie string into a SessionState
func DecodeSessionState(v string, c *encryption.Cipher) (*SessionState, error) {
	var ssj SessionStateJSON
	var ss *SessionState
	err := json.Unmarshal([]byte(v), &ssj)
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

// RawClaims access the unmodified claims that have been associated with this session or nil if
// none have been.
// Note: these claims are not serialized, and are meant only as a transient "handoff" during authentication.
func (s *SessionState) RawClaims() map[string]interface{} {
	return s.rawClaims
}

// RawClaimsValid is true when the RawClaims() will return a non-nil value.
func (s *SessionState) RawClaimsValid() bool {
	return s.rawClaimsValid
}

// SetRawClaims will assign the raw claims and mark them as valid if the value is
// not nil. This does not clone the map assigned, only assigns it so if you need
// to ensure the original is not modified, create a clone yourself.
func (s *SessionState) SetRawClaims(rawClaims map[string]interface{}) {
	s.rawClaims = rawClaims
	s.rawClaimsValid = rawClaims != nil
}

// SetRawClaimsFromIDToken will extract the full rawClaims from the ID token and
// mark them as valid.
func (s *SessionState) SetRawClaimsFromIDToken(idToken *oidc.IDToken) error {
	if err := idToken.Claims(&s.rawClaims); err != nil {
		return err
	}
	s.rawClaimsValid = true
	return nil
}

// SetRawClaimsFromSession will assign the rawClaims directly (not copy) if the
// other session `os` has them set.
func (s *SessionState) SetRawClaimsFromSession(os *SessionState) {
	if os != nil && os.rawClaimsValid {
		s.rawClaims = os.rawClaims
		s.rawClaimsValid = true
	}
}
