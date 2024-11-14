package cookie

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	pkgcookies "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/cookies"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

const (
	// Cookies are limited to 4kb for all parts
	// including the cookie name, value, attributes; IE (http.cookie).String()
	// Most browsers' max is 4096 -- but we give ourselves some leeway
	maxCookieLength = 4000
)

// Ensure CookieSessionStore implements the interface
var _ sessions.SessionStore = &SessionStore{}

// SessionStore is an implementation of the sessions.SessionStore
// interface that stores sessions in client side cookies
type SessionStore struct {
	Cookie       *options.Cookie
	CookieCipher encryption.Cipher
	Minimal      bool
}

// Save takes a sessions.SessionState and stores the information from it
// within Cookies set on the HTTP response writer
func (s *SessionStore) Save(rw http.ResponseWriter, req *http.Request, ss *sessions.SessionState) error {
	if ss.CreatedAt == nil || ss.CreatedAt.IsZero() {
		ss.CreatedAtNow()
	}
	value, err := s.cookieForSession(ss)
	if err != nil {
		return err
	}
	return s.setSessionCookie(rw, req, value, *ss.CreatedAt)
}

// Load reads sessions.SessionState information from Cookies within the
// HTTP request object
func (s *SessionStore) Load(req *http.Request) (*sessions.SessionState, error) {
	c, err := loadCookie(req, s.Cookie.Name)
	if err != nil {
		// always http.ErrNoCookie
		return nil, err
	}
	val, _, ok := encryption.Validate(c, s.Cookie.Secret, s.Cookie.Expire)
	if !ok {
		return nil, errors.New("cookie signature not valid")
	}

	session, err := sessions.DecodeSessionState(val, s.CookieCipher, true)
	if err != nil {
		return nil, err
	}
	return session, nil
}

// Clear clears any saved session information by writing a cookie to
// clear the session
func (s *SessionStore) Clear(rw http.ResponseWriter, req *http.Request) error {
	// matches CookieName, CookieName_<number>
	var cookieNameRegex = regexp.MustCompile(fmt.Sprintf("^%s(_\\d+)?$", s.Cookie.Name))

	for _, c := range req.Cookies() {
		if cookieNameRegex.MatchString(c.Name) {
			clearCookie := s.makeCookie(req, c.Name, "", time.Hour*-1)

			http.SetCookie(rw, clearCookie)
		}
	}

	return nil
}

// VerifyConnection always return no-error, as there's no connection
// in this store
func (s *SessionStore) VerifyConnection(_ context.Context) error {
	return nil
}

// cookieForSession serializes a session state for storage in a cookie
func (s *SessionStore) cookieForSession(ss *sessions.SessionState) ([]byte, error) {
	if s.Minimal && (ss.AccessToken != "" || ss.IDToken != "" || ss.RefreshToken != "") {
		minimal := *ss
		minimal.AccessToken = ""
		minimal.IDToken = ""
		minimal.RefreshToken = ""

		return minimal.EncodeSessionState(s.CookieCipher, true)
	}

	return ss.EncodeSessionState(s.CookieCipher, true)
}

// setSessionCookie adds the user's session cookie to the response
func (s *SessionStore) setSessionCookie(rw http.ResponseWriter, req *http.Request, val []byte, created time.Time) error {
	cookies, err := s.makeSessionCookie(req, val, created)
	if err != nil {
		return err
	}
	for _, c := range cookies {
		http.SetCookie(rw, c)
	}
	return nil
}

// makeSessionCookie creates an http.Cookie containing the authenticated user's
// authentication details
func (s *SessionStore) makeSessionCookie(req *http.Request, value []byte, now time.Time) ([]*http.Cookie, error) {
	strValue := string(value)
	if strValue != "" {
		var err error
		strValue, err = encryption.SignedValue(s.Cookie.Secret, s.Cookie.Name, value, now)
		if err != nil {
			return nil, err
		}
	}
	c := s.makeCookie(req, s.Cookie.Name, strValue, s.Cookie.Expire)
	if len(c.String()) > maxCookieLength {
		return splitCookie(c), nil
	}
	return []*http.Cookie{c}, nil
}

func (s *SessionStore) makeCookie(req *http.Request, name string, value string, expiration time.Duration) *http.Cookie {
	return pkgcookies.MakeCookieFromOptions(
		req,
		name,
		value,
		s.Cookie,
		expiration,
	)
}

// NewCookieSessionStore initialises a new instance of the SessionStore from
// the configuration given
func NewCookieSessionStore(opts *options.SessionOptions, cookieOpts *options.Cookie) (sessions.SessionStore, error) {
	cipher, err := encryption.NewCFBCipher(encryption.SecretBytes(cookieOpts.Secret))
	if err != nil {
		return nil, fmt.Errorf("error initialising cipher: %v", err)
	}

	return &SessionStore{
		CookieCipher: cipher,
		Cookie:       cookieOpts,
		Minimal:      opts.Cookie.Minimal,
	}, nil
}

// splitCookie reads the full cookie generated to store the session and splits
// it into a slice of cookies which fit within the 4kb cookie limit indexing
// the cookies from 0
func splitCookie(c *http.Cookie) []*http.Cookie {
	if len(c.String()) < maxCookieLength {
		return []*http.Cookie{c}
	}

	logger.Errorf("WARNING: Multiple cookies are required for this session as it exceeds the 4kb cookie limit. Please use server side session storage (eg. Redis) instead.")

	cookies := []*http.Cookie{}
	valueBytes := []byte(c.Value)
	count := 0
	for len(valueBytes) > 0 {
		newCookie := copyCookie(c)
		newCookie.Name = splitCookieName(c.Name, count)
		count++

		newCookie.Value = string(valueBytes)
		cookieLength := len(newCookie.String())
		if cookieLength <= maxCookieLength {
			valueBytes = []byte{}
		} else {
			overflow := cookieLength - maxCookieLength
			valueSize := len(valueBytes) - overflow

			newValue := valueBytes[:valueSize]
			valueBytes = valueBytes[valueSize:]
			newCookie.Value = string(newValue)
		}
		cookies = append(cookies, newCookie)
	}
	return cookies
}

func splitCookieName(name string, count int) string {
	splitName := fmt.Sprintf("%s_%d", name, count)
	overflow := len(splitName) - 256
	if overflow > 0 {
		splitName = fmt.Sprintf("%s_%d", name[:len(name)-overflow], count)
	}
	return splitName
}

// loadCookie retreieves the sessions state cookie from the http request.
// If a single cookie is present this will be returned, otherwise it attempts
// to reconstruct a cookie split up by splitCookie
func loadCookie(req *http.Request, cookieName string) (*http.Cookie, error) {
	c, err := req.Cookie(cookieName)
	if err == nil {
		return c, nil
	}
	cookies := []*http.Cookie{}
	err = nil
	count := 0
	for err == nil {
		var c *http.Cookie
		c, err = req.Cookie(splitCookieName(cookieName, count))
		if err == nil {
			cookies = append(cookies, c)
			count++
		}
	}
	if len(cookies) == 0 {
		return nil, http.ErrNoCookie
	}
	return joinCookies(cookies, cookieName)
}

// joinCookies takes a slice of cookies from the request and reconstructs the
// full session cookie
func joinCookies(cookies []*http.Cookie, cookieName string) (*http.Cookie, error) {
	if len(cookies) == 0 {
		return nil, fmt.Errorf("list of cookies must be > 0")
	}
	if len(cookies) == 1 {
		return cookies[0], nil
	}
	c := copyCookie(cookies[0])
	for i := 1; i < len(cookies); i++ {
		c.Value += cookies[i].Value
	}
	c.Name = cookieName
	return c, nil
}

func copyCookie(c *http.Cookie) *http.Cookie {
	return &http.Cookie{
		Name:       c.Name,
		Value:      c.Value,
		Path:       c.Path,
		Domain:     c.Domain,
		Expires:    c.Expires,
		RawExpires: c.RawExpires,
		MaxAge:     c.MaxAge,
		Secure:     c.Secure,
		HttpOnly:   c.HttpOnly,
		Raw:        c.Raw,
		Unparsed:   c.Unparsed,
		SameSite:   c.SameSite,
	}
}
