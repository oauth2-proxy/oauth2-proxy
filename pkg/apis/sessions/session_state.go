package sessions

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/clock"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
	"github.com/pierrec/lz4/v4"
	"github.com/vmihailenco/msgpack/v5"
)

// SessionState is used to store information about the currently authenticated user session
type SessionState struct {
	CreatedAt *time.Time `msgpack:"ca,omitempty"`
	ExpiresOn *time.Time `msgpack:"eo,omitempty"`

	AccessToken  string `msgpack:"at,omitempty"`
	IDToken      string `msgpack:"it,omitempty"`
	RefreshToken string `msgpack:"rt,omitempty"`

	Nonce []byte `msgpack:"n,omitempty"`

	CSRFToken string `msgpack:"ct,omitempty"`

	Email             string   `msgpack:"e,omitempty"`
	User              string   `msgpack:"u,omitempty"`
	Groups            []string `msgpack:"g,omitempty"`
	PreferredUsername string   `msgpack:"pu,omitempty"`

	// Internal helpers, not serialized
	Clock clock.Clock `msgpack:"-"`
	Lock  Lock        `msgpack:"-"`
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

func (s *SessionState) SetCSRFToken(t []byte) {
	s.CSRFToken = encryption.HashNonce(t)
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
	if s.CSRFToken != "" {
		o += " csrf_token:true"
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
	case "csrf_token":
		return []string{s.CSRFToken}
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
	packed, err := msgpack.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("error marshalling session state to msgpack: %w", err)
	}

	if !compress {
		return c.Encrypt(packed)
	}

	compressed, err := lz4Compress(packed)
	if err != nil {
		return nil, err
	}
	return c.Encrypt(compressed)
}

// DecodeSessionState decodes a LZ4 compressed MessagePack into a Session State
func DecodeSessionState(data []byte, c encryption.Cipher, compressed bool) (*SessionState, error) {
	decrypted, err := c.Decrypt(data)
	if err != nil {
		return nil, fmt.Errorf("error decrypting the session state: %w", err)
	}

	packed := decrypted
	if compressed {
		packed, err = lz4Decompress(decrypted)
		if err != nil {
			return nil, err
		}
	}

	var ss SessionState
	err = msgpack.Unmarshal(packed, &ss)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling data to session state: %w", err)
	}

	return &ss, nil
}

// lz4Compress compresses with LZ4
//
// The Compress:Decompress ratio is 1:Many. LZ4 gives fastest decompress speeds
// at the expense of greater compression compared to other compression
// algorithms.
func lz4Compress(payload []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	zw := lz4.NewWriter(nil)
	zw.Apply(
		lz4.BlockSizeOption(lz4.BlockSize(65536)),
		lz4.CompressionLevelOption(lz4.Fast),
	)
	zw.Reset(buf)

	reader := bytes.NewReader(payload)
	_, err := io.Copy(zw, reader)
	if err != nil {
		return nil, fmt.Errorf("error copying lz4 stream to buffer: %w", err)
	}
	err = zw.Close()
	if err != nil {
		return nil, fmt.Errorf("error closing lz4 writer: %w", err)
	}

	compressed, err := io.ReadAll(buf)
	if err != nil {
		return nil, fmt.Errorf("error reading lz4 buffer: %w", err)
	}

	return compressed, nil
}

// lz4Decompress decompresses with LZ4
func lz4Decompress(compressed []byte) ([]byte, error) {
	reader := bytes.NewReader(compressed)
	buf := new(bytes.Buffer)
	zr := lz4.NewReader(nil)
	zr.Reset(reader)
	_, err := io.Copy(buf, zr)
	if err != nil {
		return nil, fmt.Errorf("error copying lz4 stream to buffer: %w", err)
	}

	payload, err := io.ReadAll(buf)
	if err != nil {
		return nil, fmt.Errorf("error reading lz4 buffer: %w", err)
	}

	return payload, nil
}

func GenerateCSRFToken() ([]byte, error) {
	return encryption.Nonce(32)
}
