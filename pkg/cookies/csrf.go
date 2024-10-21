package cookies

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/clock"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
	"github.com/vmihailenco/msgpack/v5"
)

// CSRF manages various nonces stored in the CSRF cookie during the initial
// authentication flows.
type CSRF interface {
	HashOAuthState() string
	HashOIDCNonce() string
	CheckOAuthState(string) bool
	CheckOIDCNonce(string) bool
	GetCodeVerifier() string

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

	// CodeVerifier holds the unobfuscated PKCE code verification string
	// which is used to compare the code challenge when exchanging the
	// authentication code.
	CodeVerifier string `msgpack:"cv,omitempty"`

	cookieOpts *options.Cookie
	time       clock.Clock
}

// csrtStateTrim will indicate the length of the state trimmed for the name of the csrf cookie
const csrfStateLength int = 9

// NewCSRF creates a CSRF with random nonces
func NewCSRF(opts *options.Cookie, codeVerifier string) (CSRF, error) {
	state, err := encryption.Nonce(32)
	if err != nil {
		return nil, err
	}
	nonce, err := encryption.Nonce(32)
	if err != nil {
		return nil, err
	}

	return &csrf{
		OAuthState:   state,
		OIDCNonce:    nonce,
		CodeVerifier: codeVerifier,

		cookieOpts: opts,
	}, nil
}

// LoadCSRFCookie loads a CSRF object from a request's CSRF cookie
func LoadCSRFCookie(req *http.Request, cookieName string, opts *options.Cookie) (CSRF, error) {
	cookies := req.Cookies()
	for _, cookie := range cookies {
		if cookie.Name != cookieName {
			continue
		}

		csrf, err := decodeCSRFCookie(cookie, opts)
		if err != nil {
			continue
		}

		return csrf, nil
	}

	return nil, fmt.Errorf("CSRF cookie with name '%v' was not found", cookieName)
}

// GenerateCookieName in case cookie options state that CSRF cookie has fixed name then set fixed name, otherwise
// build name based on the state
func GenerateCookieName(opts *options.Cookie, state string) string {
	stateSubstring := ""
	if opts.CSRFPerRequest {
		// csrfCookieName will include a substring of the state to enable multiple csrf cookies
		// in case of parallel requests
		stateSubstring = ExtractStateSubstring(state)
	}
	return csrfCookieName(opts, stateSubstring)
}

func (c *csrf) GetCodeVerifier() string {
	return c.CodeVerifier
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

	cookie := MakeCookieFromOptions(
		req,
		c.cookieName(),
		encoded,
		c.cookieOpts,
		c.cookieOpts.CSRFExpire,
		c.time.Now(),
	)
	http.SetCookie(rw, cookie)

	return cookie, nil
}

// ClearCookie removes the CSRF cookie
func (c *csrf) ClearCookie(rw http.ResponseWriter, req *http.Request) {
	http.SetCookie(rw, MakeCookieFromOptions(
		req,
		c.cookieName(),
		"",
		c.cookieOpts,
		time.Hour*-1,
		c.time.Now(),
	))
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

	return encryption.SignedValue(c.cookieOpts.Secret, c.cookieName(), encrypted, c.time.Now())
}

// decodeCSRFCookie validates the signature then decrypts and decodes a CSRF
// cookie into a CSRF struct
func decodeCSRFCookie(cookie *http.Cookie, opts *options.Cookie) (*csrf, error) {
	val, _, ok := encryption.Validate(cookie, opts.Secret, opts.Expire)
	if !ok {
		return nil, errors.New("CSRF cookie failed validation")
	}

	decrypted, err := decrypt(val, opts)
	if err != nil {
		return nil, err
	}

	// Valid cookie, Unmarshal the CSRF
	csrf := &csrf{cookieOpts: opts}
	err = msgpack.Unmarshal(decrypted, csrf)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling data to CSRF: %v", err)
	}

	return csrf, nil
}

// cookieName returns the CSRF cookie's name
func (c *csrf) cookieName() string {
	stateSubstring := ""
	if c.cookieOpts.CSRFPerRequest {
		stateSubstring = encryption.HashNonce(c.OAuthState)[0 : csrfStateLength-1]
	}
	return csrfCookieName(c.cookieOpts, stateSubstring)
}

func csrfCookieName(opts *options.Cookie, stateSubstring string) string {
	if stateSubstring == "" {
		return fmt.Sprintf("%v_csrf", opts.Name)
	}
	return fmt.Sprintf("%v_%v_csrf", opts.Name, stateSubstring)
}

// ExtractStateSubstring extract the initial state characters, to add it to the CSRF cookie name
func ExtractStateSubstring(state string) string {
	lastChar := csrfStateLength - 1
	stateSubstring := ""
	if lastChar <= len(state) {
		stateSubstring = state[0:lastChar]
	}
	return stateSubstring
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
	return encryption.NewCFBCipher(encryption.SecretBytes(opts.Secret))
}
