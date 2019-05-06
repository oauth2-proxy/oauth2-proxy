package cookie

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pusher/oauth2_proxy/cookie"
	"github.com/pusher/oauth2_proxy/pkg/apis/options"
	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/sessions/utils"
)

// Ensure CookieSessionStore implements the interface
var _ sessions.SessionStore = &SessionStore{}

// SessionStore is an implementation of the sessions.SessionStore
// interface that stores sessions in client side cookies
type SessionStore struct {
	CookieCipher *cookie.Cipher
	CookieExpire time.Duration
	CookieName   string
	CookieSecret string
}

// SaveSession takes a sessions.SessionState and stores the information from it
// within Cookies set on the HTTP response writer
func (s *SessionStore) SaveSession(rw http.ResponseWriter, req *http.Request, ss *sessions.SessionState) error {
	return fmt.Errorf("method not implemented")
}

// LoadSession reads sessions.SessionState information from Cookies within the
// HTTP request object
func (s *SessionStore) LoadSession(req *http.Request) (*sessions.SessionState, error) {
	c, err := loadCookie(req, s.CookieName)
	if err != nil {
		// always http.ErrNoCookie
		return nil, fmt.Errorf("Cookie %q not present", s.CookieName)
	}
	val, _, ok := cookie.Validate(c, s.CookieSecret, s.CookieExpire)
	if !ok {
		return nil, errors.New("Cookie Signature not valid")
	}

	session, err := utils.SessionFromCookie(val, s.CookieCipher)
	if err != nil {
		return nil, err
	}
	return session, nil
}

// ClearSession clears any saved session information by writing a cookie to
// clear the session
func (s *SessionStore) ClearSession(rw http.ResponseWriter, req *http.Request) error {
	return fmt.Errorf("method not implemented")
}

// NewCookieSessionStore initialises a new instance of the SessionStore from
// the configuration given
func NewCookieSessionStore(opts options.CookieStoreOptions, cookieOpts *options.CookieOptions) (sessions.SessionStore, error) {
	var cipher *cookie.Cipher
	if len(cookieOpts.CookieSecret) > 0 {
		var err error
		cipher, err = cookie.NewCipher(utils.SecretBytes(cookieOpts.CookieSecret))
		if err != nil {
			return nil, fmt.Errorf("unable to create cipher: %v", err)
		}
	}

	return &SessionStore{
		CookieCipher: cipher,
		CookieExpire: cookieOpts.CookieExpire,
		CookieName:   cookieOpts.CookieName,
		CookieSecret: cookieOpts.CookieSecret,
	}, nil
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
		c, err = req.Cookie(fmt.Sprintf("%s_%d", cookieName, count))
		if err == nil {
			cookies = append(cookies, c)
			count++
		}
	}
	if len(cookies) == 0 {
		return nil, fmt.Errorf("Could not find cookie %s", cookieName)
	}
	return joinCookies(cookies)
}

// joinCookies takes a slice of cookies from the request and reconstructs the
// full session cookie
func joinCookies(cookies []*http.Cookie) (*http.Cookie, error) {
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
	c.Name = strings.TrimRight(c.Name, "_0")
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
	}
}
