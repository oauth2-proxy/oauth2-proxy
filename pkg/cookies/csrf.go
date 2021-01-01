package cookies

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
	"github.com/vmihailenco/msgpack/v4"
)

var now = time.Now

// CSRF manages various nonces stored in the CSRF cookie during the initial
// authentication flows.
type CSRF struct {
	// State holds the OAuth2 state parameter's nonce component set in the
	// initial authentication request and mirrored back in the callback
	// redirect from the IdP for CSRF protection.
	State []byte `msgpack:"s,omitempty"`

	// Nonce holds the OIDC nonce parameter used in the initial authentication
	// and then set in all subsequent OIDC ID Tokens as the nonce claim. This
	// is used to mitigate reply attacks.
	Nonce []byte `msgpack:"n,omitempty"`

	cookieOpts *options.Cookie
}

// NewCSRF creates a CSRF with random nonces
func NewCSRF(opts *options.Cookie) (*CSRF, error) {
	state, err := encryption.Nonce()
	if err != nil {
		return nil, err
	}
	nonce, err := encryption.Nonce()
	if err != nil {
		return nil, err
	}

	return &CSRF{
		State: state,
		Nonce: nonce,

		cookieOpts: opts,
	}, nil
}

// HashState returns the hash of the OAuth state nonce
func (c CSRF) HashState() string {
	return encryption.HashNonce(c.State)
}

// HashNonce returns the hash of the OIDC nonce
func (c CSRF) HashNonce() string {
	return encryption.HashNonce(c.Nonce)
}

// CheckNonce compares the OAuth state nonce against a potential hash of it
func (c CSRF) CheckState(hashed string) bool {
	return encryption.CheckNonce(c.State, hashed)
}

// CheckNonce compares the OIDC nonce against a potential hash of it
func (c CSRF) CheckNonce(hashed string) bool {
	return encryption.CheckNonce(c.Nonce, hashed)
}

// SetCookie encodes the CSRF to a signed cookie and sets it on the ResponseWriter
func (c CSRF) SetCookie(rw http.ResponseWriter, req *http.Request) error {
	encoded, err := c.EncodeCookie()
	if err != nil {
		return err
	}

	http.SetCookie(rw, MakeCookieFromOptions(
		req,
		c.CookieName(),
		encoded,
		c.cookieOpts,
		c.cookieOpts.Expire,
		now(),
	))

	return nil
}

// LoadCSRFCookie loads a CSRF object from a request's CSRF cookie
func LoadCSRFCookie(req *http.Request, opts *options.Cookie) (*CSRF, error) {
	cookie, err := req.Cookie(csrfCookieName(opts))
	if err != nil {
		// Don't wrap this error to allow `err == http.ErrNoCookie` checks
		return nil, err
	}

	return DecodeCSRFCookie(cookie, opts)
}

// ClearCookie removes the CSRF cookie
func (c CSRF) ClearCookie(rw http.ResponseWriter, req *http.Request) {
	http.SetCookie(rw, MakeCookieFromOptions(
		req,
		c.CookieName(),
		"",
		c.cookieOpts,
		time.Hour*-1,
		now(),
	))
}

// EncodeCookie MessagePack encodes and encrypts the CSRF and then creates a
// signed cookie value
func (c CSRF) EncodeCookie() (string, error) {
	packed, err := msgpack.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("error marshalling CSRF to msgpack: %v", err)
	}

	encrypted, err := encrypt(packed, c.cookieOpts)
	if err != nil {
		return "", err
	}

	return encryption.SignedValue(c.cookieOpts.Secret, c.CookieName(), encrypted, now())
}

// DecodeCSRFCookie validates the signature then decrypts and decodes a CSRF
// cookie into a CSRF struct
func DecodeCSRFCookie(cookie *http.Cookie, opts *options.Cookie) (*CSRF, error) {
	val, _, ok := encryption.Validate(cookie, opts.Secret, opts.Expire)
	if !ok {
		return nil, errors.New("CSRF cookie failed validation")
	}

	decrypted, err := decrypt(val, opts)
	if err != nil {
		return nil, err
	}

	// Valid cookie, Unmarshal the CSRF
	csrf := &CSRF{cookieOpts: opts}
	err = msgpack.Unmarshal(decrypted, csrf)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling data to CSRF: %v", err)
	}

	return csrf, nil
}

// CookieName returns the CSRF cookie's name derived from the base
// session cookie name
func (c CSRF) CookieName() string {
	return csrfCookieName(c.cookieOpts)
}

func csrfCookieName(opts *options.Cookie) string {
	return fmt.Sprintf("%v_csrf", opts.Name)
}

func encrypt(data []byte, opts *options.Cookie) ([]byte, error) {
	cipher, err := makeCipher(opts)
	if err != nil {
		return nil, err
	}
	return cipher.Encrypt(data)
}

func decrypt(data []byte, opts *options.Cookie) ([]byte, error) {
	cipher, err := makeCipher(opts)
	if err != nil {
		return nil, err
	}
	return cipher.Decrypt(data)
}

func makeCipher(opts *options.Cookie) (encryption.Cipher, error) {
	return encryption.NewCFBCipher([]byte(opts.Secret))
}
