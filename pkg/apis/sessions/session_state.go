package sessions

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
	"time"
	"unicode/utf8"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
	"github.com/pierrec/lz4"
	"github.com/vmihailenco/msgpack/v5"
)

// SessionState is used to store information about the currently authenticated user session
type SessionState struct {
	CreatedAt *time.Time `msgpack:"ca,omitempty"`
	ExpiresOn *time.Time `msgpack:"eo,omitempty"`

	AccessToken  string `msgpack:"at,omitempty"`
	IDToken      string `msgpack:"it,omitempty"`
	RefreshToken string `msgpack:"rt,omitempty"`

	Email             string   `msgpack:"e,omitempty"`
	User              string   `msgpack:"u,omitempty"`
	Groups            []string `msgpack:"g,omitempty"`
	PreferredUsername string   `msgpack:"pu,omitempty"`
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

	err = ss.validate()
	if err != nil {
		return nil, err
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
	zw.Header = lz4.Header{
		BlockMaxSize:     65536,
		CompressionLevel: 0,
	}
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

	compressed, err := ioutil.ReadAll(buf)
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

	payload, err := ioutil.ReadAll(buf)
	if err != nil {
		return nil, fmt.Errorf("error reading lz4 buffer: %w", err)
	}

	return payload, nil
}

// validate ensures the decoded session is non-empty and contains valid data
//
// Non-empty check is needed due to ensure the non-authenticated AES-CFB
// decryption doesn't result in garbage data that collides with a valid
// MessagePack header bytes (which MessagePack will unmarshal to an empty
// default SessionState). <1% chance, but observed with random test data.
//
// UTF-8 check ensures the strings are valid and not raw bytes overloaded
// into Latin-1 encoding. The occurs when legacy unencrypted fields are
// decrypted with AES-CFB which results in random bytes.
func (s *SessionState) validate() error {
	for _, field := range []string{
		s.User,
		s.Email,
		s.PreferredUsername,
		s.AccessToken,
		s.IDToken,
		s.RefreshToken,
	} {
		if !utf8.ValidString(field) {
			return errors.New("invalid non-UTF8 field in session")
		}
	}

	empty := new(SessionState)
	if reflect.DeepEqual(*s, *empty) {
		return errors.New("invalid empty session unmarshalled")
	}

	return nil
}
