package sessions

import (
	"context"
	"fmt"
	"time"

	"encoding/json"

	"github.com/Jing-ze/oauth2-proxy/pkg/clock"
	"github.com/Jing-ze/oauth2-proxy/pkg/encryption"
)

// // SessionState is used to store information about the currently authenticated user session
type SessionState struct {
	CreatedAt *time.Time `json:"ca,omitempty"`
	ExpiresOn *time.Time `json:"eo,omitempty"`

	AccessToken  string `json:"at,omitempty"`
	IDToken      string `json:"it,omitempty"`
	RefreshToken string `json:"rt,omitempty"`

	Nonce []byte `json:"n,omitempty"`

	Email             string   `json:"e,omitempty"`
	User              string   `json:"u,omitempty"`
	Groups            []string `json:"g,omitempty"`
	PreferredUsername string   `json:"pu,omitempty"`

	// Internal helpers, not serialized
	Clock clock.Clock `json:"-"`
	Lock  Lock        `json:"-"`
}

func (s *SessionState) ObtainLock(ctx context.Context, expiration time.Duration) error {
	if s.Lock == nil {
		s.Lock = &NoOpLock{}
	}
	return s.Lock.Obtain(ctx, expiration)
}

func (s *SessionState) RefreshLock(ctx context.Context, expiration time.Duration) error {
	if s.Lock == nil {
		s.Lock = &NoOpLock{}
	}
	return s.Lock.Refresh(ctx, expiration)
}

func (s *SessionState) ReleaseLock(ctx context.Context) error {
	if s.Lock == nil {
		s.Lock = &NoOpLock{}
	}
	return s.Lock.Release(ctx)
}

func (s *SessionState) PeekLock(ctx context.Context) (bool, error) {
	if s.Lock == nil {
		s.Lock = &NoOpLock{}
	}
	return s.Lock.Peek(ctx)
}

// CreatedAtNow sets a SessionState's CreatedAt to now
func (s *SessionState) CreatedAtNow() {
	now := s.Clock.Now()
	s.CreatedAt = &now
}

// SetExpiresOn sets an expiration
func (s *SessionState) SetExpiresOn(exp time.Time) {
	s.ExpiresOn = &exp
}

// ExpiresIn sets an expiration a certain duration from CreatedAt.
// CreatedAt will be set to time.Now if it is unset.
func (s *SessionState) ExpiresIn(d time.Duration) {
	if s.CreatedAt == nil {
		s.CreatedAtNow()
	}
	exp := s.CreatedAt.Add(d)
	s.ExpiresOn = &exp
}

// IsExpired checks whether the session has expired
func (s *SessionState) IsExpired() bool {
	if s.ExpiresOn != nil && !s.ExpiresOn.IsZero() && s.ExpiresOn.Before(s.Clock.Now()) {
		return true
	}
	return false
}

// Age returns the age of a session
func (s *SessionState) Age() time.Duration {
	if s.CreatedAt != nil && !s.CreatedAt.IsZero() {
		return s.Clock.Now().Truncate(time.Second).Sub(*s.CreatedAt)
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
	if s.CreatedAt != nil && !s.CreatedAt.IsZero() {
		o += fmt.Sprintf(" created:%s", s.CreatedAt)
	}
	if s.ExpiresOn != nil && !s.ExpiresOn.IsZero() {
		o += fmt.Sprintf(" expires:%s", s.ExpiresOn)
	}
	if s.RefreshToken != "" {
		o += " refresh_token:true"
	}
	if len(s.Groups) > 0 {
		o += fmt.Sprintf(" groups:%v", s.Groups)
	}
	return o + "}"
}

func (s *SessionState) GetClaim(claim string) []string {
	if s == nil {
		return []string{}
	}
	switch claim {
	case "access_token":
		return []string{s.AccessToken}
	case "id_token":
		return []string{s.IDToken}
	case "created_at":
		return []string{s.CreatedAt.String()}
	case "expires_on":
		return []string{s.ExpiresOn.String()}
	case "refresh_token":
		return []string{s.RefreshToken}
	case "email":
		return []string{s.Email}
	case "user":
		return []string{s.User}
	case "groups":
		groups := make([]string, len(s.Groups))
		copy(groups, s.Groups)
		return groups
	case "preferred_username":
		return []string{s.PreferredUsername}
	default:
		return []string{}
	}
}

// CheckNonce compares the Nonce against a potential hash of it
func (s *SessionState) CheckNonce(hashed string) bool {
	return encryption.CheckNonce(s.Nonce, hashed)
}

// EncodeSessionState returns an encrypted, lz4 compressed, MessagePack encoded session
func (s *SessionState) EncodeSessionState(c encryption.Cipher, compress bool) ([]byte, error) {
	packed, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("error marshalling session state to msgpack: %w", err)
	}

	return c.Encrypt(packed)
}

// DecodeSessionState decodes a LZ4 compressed MessagePack into a Session State
func DecodeSessionState(data []byte, c encryption.Cipher, compressed bool) (*SessionState, error) {
	decrypted, err := c.Decrypt(data)
	if err != nil {
		return nil, fmt.Errorf("error decrypting the session state: %w", err)
	}

	packed := decrypted

	var ss SessionState
	err = json.Unmarshal(packed, &ss)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling data to session state: %w", err)
	}

	return &ss, nil
}
