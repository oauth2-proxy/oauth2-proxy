package cookie

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/pusher/oauth2_proxy/cookie"
	"github.com/pusher/oauth2_proxy/pkg/apis/options"
	"github.com/pusher/oauth2_proxy/pkg/apis/sessions"
	"github.com/pusher/oauth2_proxy/pkg/cookies"
	"github.com/pusher/oauth2_proxy/pkg/sessions/utils"
)

const (
	// Cookies are limited to 4kb including the length of the cookie name,
	// the cookie name can be up to 256 bytes
	maxCookieLength = 3840
)

// Ensure CookieSessionStore implements the interface
var _ sessions.SessionStore = &SessionStore{}

// SessionStore is an implementation of the sessions.SessionStore
// interface that stores sessions in client side cookies
type SessionStore struct {
	CookieCipher   *cookie.Cipher
	CookieDomain   string
	CookieExpire   time.Duration
	CookieHTTPOnly bool
	CookieName     string
	CookiePath     string
	CookieSecret   string
	CookieSecure   bool
}

// Save takes a sessions.SessionState and stores the information from it
// within Cookies set on the HTTP response writer
func (s *SessionStore) Save(rw http.ResponseWriter, req *http.Request, ss *sessions.SessionState) error {
	value, err := utils.CookieForSession(ss, s.CookieCipher)
	if err != nil {
		return err
	}
	s.setSessionCookie(rw, req, value)
	return nil
}

// Load reads sessions.SessionState information from Cookies within the
// HTTP request object
func (s *SessionStore) Load(req *http.Request) (*sessions.SessionState, error) {
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

// Clear clears any saved session information by writing a cookie to
// clear the session
func (s *SessionStore) Clear(rw http.ResponseWriter, req *http.Request) error {
	var cookies []*http.Cookie

	// matches CookieName, CookieName_<number>
	var cookieNameRegex = regexp.MustCompile(fmt.Sprintf("^%s(_\\d+)?$", s.CookieName))

	for _, c := range req.Cookies() {
		if cookieNameRegex.MatchString(c.Name) {
			clearCookie := s.makeCookie(req, c.Name, "", time.Hour*-1)

			http.SetCookie(rw, clearCookie)
			cookies = append(cookies, clearCookie)
		}
	}

	return nil
}

// setSessionCookie adds the user's session cookie to the response
func (s *SessionStore) setSessionCookie(rw http.ResponseWriter, req *http.Request, val string) {
	for _, c := range s.makeSessionCookie(req, val, s.CookieExpire, time.Now()) {
		http.SetCookie(rw, c)
	}
}

// makeSessionCookie creates an http.Cookie containing the authenticated user's
// authentication details
func (s *SessionStore) makeSessionCookie(req *http.Request, value string, expiration time.Duration, now time.Time) []*http.Cookie {
	if value != "" {
		value = cookie.SignedValue(s.CookieSecret, s.CookieName, value, now)
	}
	c := s.makeCookie(req, s.CookieName, value, expiration)
	if len(c.Value) > 4096-len(s.CookieName) {
		return splitCookie(c)
	}
	return []*http.Cookie{c}
}

func (s *SessionStore) makeCookie(req *http.Request, name string, value string, expiration time.Duration) *http.Cookie {
	return cookies.MakeCookie(
		req,
		name,
		value,
		s.CookiePath,
		s.CookieDomain,
		s.CookieHTTPOnly,
		s.CookieSecure,
		expiration,
		time.Now(),
	)
}

// NewCookieSessionStore initialises a new instance of the SessionStore from
// the configuration given
func NewCookieSessionStore(opts options.CookieStoreOptions, cookieOpts *options.CookieOptions) (sessions.SessionStore, error) {
	var cipher *cookie.Cipher
	if opts.EnableCipher {
		var err error
		cipher, err = cookie.NewCipher(utils.SecretBytes(cookieOpts.CookieSecret))
		if err != nil {
			return nil, fmt.Errorf("unable to create cipher: %v", err)
		}
	}

	return &SessionStore{
		CookieCipher:   cipher,
		CookieDomain:   cookieOpts.CookieDomain,
		CookieExpire:   cookieOpts.CookieExpire,
		CookieHTTPOnly: cookieOpts.CookieHTTPOnly,
		CookieName:     cookieOpts.CookieName,
		CookiePath:     cookieOpts.CookiePath,
		CookieSecret:   cookieOpts.CookieSecret,
		CookieSecure:   cookieOpts.CookieSecure,
	}, nil
}

// splitCookie reads the full cookie generated to store the session and splits
// it into a slice of cookies which fit within the 4kb cookie limit indexing
// the cookies from 0
func splitCookie(c *http.Cookie) []*http.Cookie {
	if len(c.Value) < maxCookieLength {
		return []*http.Cookie{c}
	}
	cookies := []*http.Cookie{}
	valueBytes := []byte(c.Value)
	count := 0
	for len(valueBytes) > 0 {
		new := copyCookie(c)
		new.Name = fmt.Sprintf("%s_%d", c.Name, count)
		count++
		if len(valueBytes) < maxCookieLength {
			new.Value = string(valueBytes)
			valueBytes = []byte{}
		} else {
			newValue := valueBytes[:maxCookieLength]
			valueBytes = valueBytes[maxCookieLength:]
			new.Value = string(newValue)
		}
		cookies = append(cookies, new)
	}
	return cookies
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
