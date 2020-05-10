package sessions

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pierrec/lz4"
	"github.com/vmihailenco/msgpack/v4"
	"io"
	"io/ioutil"
	"time"
	"unicode/utf8"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/encryption"
)

// SessionState is used to store information about the currently authenticated user session
type SessionState struct {
	AccessToken       string    `json:",omitempty" msgpack:"at,omitempty"`
	IDToken           string    `json:",omitempty" msgpack:"it,omitempty"`
	CreatedAt         *time.Time `json:",omitempty" msgpack:"ca,omitempty"`
	ExpiresOn         *time.Time `json:",omitempty" msgpack:"eo,omitempty"`
	RefreshToken      string    `json:",omitempty" msgpack:"rt,omitempty"`
	Email             string    `json:",omitempty" msgpack:"e,omitempty"`
	User              string    `json:",omitempty" msgpack:"u,omitempty"`
	PreferredUsername string    `json:",omitempty" msgpack:"pu,omitempty"`
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

// EncodeSessionState returns an encrypted, lz4 compressed, MessagePack encoded session
func (s *SessionState) EncodeSessionState(c encryption.Cipher, compress bool) ([]byte, error) {
	// Marshal to MessagePack
	packed, err := msgpack.Marshal(s)
	if err != nil {
		return []byte{}, err
	}

	if !compress {
		// Encrypt the msgpack encoded
		return c.Encrypt(packed)
	}

	// Compress the packed encoding
	// The Compress:Decompress ratio is 1:Many. LZ4 gives fastest decompress speeds
	buf := new(bytes.Buffer)
	zw := lz4.NewWriter(nil)
	zw.Header = lz4.Header{
		BlockMaxSize:     65536,
		CompressionLevel: 0,
	}
	zw.Reset(buf)

	reader := bytes.NewReader(packed)
	_, err = io.Copy(zw, reader)
	if err != nil {
		return []byte{}, err
	}
	_ = zw.Close()

	compressed, err := ioutil.ReadAll(buf)
	if err != nil {
		return []byte{}, err
	}

	// Encrypt the compressed
	return c.Encrypt(compressed)
}

// DecodeSessionState decodes a LZ4 compressed MessagePack into a Session State
func DecodeSessionState(data []byte, c encryption.Cipher, compressed bool) (*SessionState, error) {
	// Decrypt
	decrypted, err := c.Decrypt(data)
	if err != nil {
		return nil, err
	}

	packed := decrypted
	if compressed {
		// LZ4 Decompress
		reader := bytes.NewReader(decrypted)
		buf := new(bytes.Buffer)
		zr := lz4.NewReader(nil)
		zr.Reset(reader)
		_, err = io.Copy(buf, zr)
		if err != nil {
			return nil, err
		}

		packed, err = ioutil.ReadAll(buf)
		if err != nil {
			return nil, err
		}
	}

	// Decode MessagePack
	var ss *SessionState
	err = msgpack.Unmarshal(packed, &ss)
	if err != nil {
		return nil, err
	}

	return ss, nil
}

// LegacyV5DecodeSessionState decodes a legacy JSON session cookie string into a SessionState
func LegacyV5DecodeSessionState(v string, c encryption.Cipher) (*SessionState, error) {
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