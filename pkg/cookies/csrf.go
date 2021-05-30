package cookies

import (
	"fmt"
	"net/http"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/clock"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
	"github.com/vmihailenco/msgpack/v4"
)

// CSRF manages various nonces stored in the CSRF cookie during the initial
// authentication flows.
type CSRF interface {
	HashOAuthState() string
	HashOIDCNonce() string
	CheckOAuthState(string) bool
	CheckOIDCNonce(string) bool

	SetSessionNonce(s *sessions.SessionState)

	SetCookie(http.ResponseWriter, *http.Request) (*http.Cookie, error)
	ClearCookie(http.ResponseWriter, *http.Request)
}

type csrf struct {
	// OAuthState holds the OAuth2 state parameter's nonce component set in the
	// initial authentication request and mirrored back in the callback
	// redirect from the IdP for CSRF protection.
	OAuthState []byte `msgpack:"s,omitempty"`

	// OIDCNonce holds the OIDC nonce parameter used in the initial authentication
	// and then set in all subsequent OIDC ID Tokens as the nonce claim. This
	// is used to mitigate replay attacks.
	OIDCNonce []byte `msgpack:"n,omitempty"`

	builder          Builder
	encryptionSecret string
	time             clock.Clock
}

// NewCSRF creates a CSRF with random nonces
func NewCSRF(builder Builder, secret string) (CSRF, error) {
	state, err := encryption.Nonce()
	if err != nil {
		return nil, err
	}
	nonce, err := encryption.Nonce()
	if err != nil {
		return nil, err
	}

	return &csrf{
		OAuthState: state,
		OIDCNonce:  nonce,

		builder:          builder,
		encryptionSecret: secret,
	}, nil
}

// LoadCSRFCookie loads a CSRF object from a request's CSRF cookie
func LoadCSRFCookie(req *http.Request, builder Builder, secret string) (CSRF, error) {
	cookieValue, err := builder.ValidateRequest(req)
	if err != nil {
		return nil, fmt.Errorf("failed to validate CSRF cookie value: %v", err)
	}

	return decodeCSRFCookie(cookieValue, builder, secret)
}

// HashOAuthState returns the hash of the OAuth state nonce
func (c *csrf) HashOAuthState() string {
	return encryption.HashNonce(c.OAuthState)
}

// HashOIDCNonce returns the hash of the OIDC nonce
func (c *csrf) HashOIDCNonce() string {
	return encryption.HashNonce(c.OIDCNonce)
}

// CheckOAuthState compares the OAuth state nonce against a potential
// hash of it
func (c *csrf) CheckOAuthState(hashed string) bool {
	return encryption.CheckNonce(c.OAuthState, hashed)
}

// CheckOIDCNonce compares the OIDC nonce against a potential hash of it
func (c *csrf) CheckOIDCNonce(hashed string) bool {
	return encryption.CheckNonce(c.OIDCNonce, hashed)
}

// SetSessionNonce sets the OIDCNonce on a SessionState
func (c *csrf) SetSessionNonce(s *sessions.SessionState) {
	s.Nonce = c.OIDCNonce
}

// SetCookie encodes the CSRF to a signed cookie and sets it on the ResponseWriter
func (c *csrf) SetCookie(rw http.ResponseWriter, req *http.Request) (*http.Cookie, error) {
	encoded, err := c.encodeCookie()
	if err != nil {
		return nil, err
	}

	cookie, err := c.builder.
		WithStart(c.time.Now()).
		MakeCookie(req, encoded)
	if err != nil {
		return nil, err
	}
	http.SetCookie(rw, cookie)

	return cookie, nil
}

// ClearCookie removes the CSRF cookie
func (c *csrf) ClearCookie(rw http.ResponseWriter, req *http.Request) error {
	cookie, err := c.builder.
		WithExpiration(time.Hour*-1).
		WithStart(c.time.Now()).
		MakeCookie(req, "")
	if err != nil {
		return fmt.Errorf("could not create cookie: %v", err)
	}
	http.SetCookie(rw, cookie)
}

// encodeCookie MessagePack encodes and encrypts the CSRF and then creates a
// signed cookie value
func (c *csrf) encodeCookie() (string, error) {
	packed, err := msgpack.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("error marshalling CSRF to msgpack: %v", err)
	}

	encrypted, err := encrypt(packed, c.cookieOpts)
	if err != nil {
		return "", err
	}

	return string(encrypted), nil
}

// decodeCSRFCookie validates the signature then decrypts and decodes a CSRF
// cookie into a CSRF struct
func decodeCSRFCookie(cookieValue string, builder Builder, secret string) (*csrf, error) {
	decrypted, err := decrypt([]byte(cookieValue), secret)
	if err != nil {
		return nil, err
	}

	// Valid cookie, Unmarshal the CSRF
	csrf := &csrf{builder: builder, encryptionSecret: secret}
	if err := msgpack.Unmarshal(decrypted, csrf); err != nil {
		return nil, fmt.Errorf("error unmarshalling data to CSRF: %v", err)
	}

	return csrf, nil
}

func encrypt(data []byte, secret string) ([]byte, error) {
	cipher, err := makeCipher(secret)
	if err != nil {
		return nil, err
	}
	return cipher.Encrypt(data)
}

func decrypt(data []byte, secret string) ([]byte, error) {
	cipher, err := makeCipher(secret)
	if err != nil {
		return nil, err
	}
	return cipher.Decrypt(data)
}

func makeCipher(secret string) (encryption.Cipher, error) {
	return encryption.NewCFBCipher(encryption.SecretBytes(secret))
}
