package main

import (
	b64 "encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/mbland/hmacauth"
	"github.com/pusher/oauth2_proxy/cookie"
	"github.com/pusher/oauth2_proxy/logger"
	"github.com/pusher/oauth2_proxy/providers"
	"github.com/yhat/wsutil"
)

const (
	// SignatureHeader is the name of the request header containing the GAP Signature
	// Part of hmacauth
	SignatureHeader = "GAP-Signature"

	httpScheme  = "http"
	httpsScheme = "https"

	// Cookies are limited to 4kb including the length of the cookie name,
	// the cookie name can be up to 256 bytes
	maxCookieLength = 3840

	applicationJSON = "application/json"
)

// SignatureHeaders contains the headers to be signed by the hmac algorithm
// Part of hmacauth
var SignatureHeaders = []string{
	"Content-Length",
	"Content-Md5",
	"Content-Type",
	"Date",
	"Authorization",
	"X-Forwarded-User",
	"X-Forwarded-Email",
	"X-Forwarded-Access-Token",
	"Cookie",
	"Gap-Auth",
}

// OAuthProxy is the main authentication proxy
type OAuthProxy struct {
	CookieSeed     string
	CookieName     string
	CSRFCookieName string
	CookieDomain   string
	CookiePath     string
	CookieSecure   bool
	CookieHTTPOnly bool
	CookieExpire   time.Duration
	CookieRefresh  time.Duration
	Validator      func(string) bool

	RobotsPath        string
	PingPath          string
	SignInPath        string
	SignOutPath       string
	OAuthStartPath    string
	OAuthCallbackPath string
	AuthOnlyPath      string

	redirectURL         *url.URL // the url to receive requests at
	whitelistDomains    []string
	provider            providers.Provider
	ProxyPrefix         string
	SignInMessage       string
	HtpasswdFile        *HtpasswdFile
	DisplayHtpasswdForm bool
	serveMux            http.Handler
	SetXAuthRequest     bool
	PassBasicAuth       bool
	SkipProviderButton  bool
	PassUserHeaders     bool
	BasicAuthPassword   string
	PassAccessToken     bool
	SetAuthorization    bool
	PassAuthorization   bool
	CookieCipher        *cookie.Cipher
	skipAuthRegex       []string
	skipAuthPreflight   bool
	compiledRegex       []*regexp.Regexp
	templates           *template.Template
	Footer              string
}

// UpstreamProxy represents an upstream server to proxy to
type UpstreamProxy struct {
	upstream  string
	handler   http.Handler
	wsHandler http.Handler
	auth      hmacauth.HmacAuth
}

// ServeHTTP proxies requests to the upstream provider while signing the
// request headers
func (u *UpstreamProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("GAP-Upstream-Address", u.upstream)
	if u.auth != nil {
		r.Header.Set("GAP-Auth", w.Header().Get("GAP-Auth"))
		u.auth.SignRequest(r)
	}
	if u.wsHandler != nil && strings.ToLower(r.Header.Get("Connection")) == "upgrade" && r.Header.Get("Upgrade") == "websocket" {
		u.wsHandler.ServeHTTP(w, r)
	} else {
		u.handler.ServeHTTP(w, r)
	}

}

// NewReverseProxy creates a new reverse proxy for proxying requests to upstream
// servers
func NewReverseProxy(target *url.URL, flushInterval time.Duration) (proxy *httputil.ReverseProxy) {
	proxy = httputil.NewSingleHostReverseProxy(target)
	proxy.FlushInterval = flushInterval
	return proxy
}

func setProxyUpstreamHostHeader(proxy *httputil.ReverseProxy, target *url.URL) {
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req)
		// use RequestURI so that we aren't unescaping encoded slashes in the request path
		req.Host = target.Host
		req.URL.Opaque = req.RequestURI
		req.URL.RawQuery = ""
	}
}

func setProxyDirector(proxy *httputil.ReverseProxy) {
	director := proxy.Director
	proxy.Director = func(req *http.Request) {
		director(req)
		// use RequestURI so that we aren't unescaping encoded slashes in the request path
		req.URL.Opaque = req.RequestURI
		req.URL.RawQuery = ""
	}
}

// NewFileServer creates a http.Handler to serve files from the filesystem
func NewFileServer(path string, filesystemPath string) (proxy http.Handler) {
	return http.StripPrefix(path, http.FileServer(http.Dir(filesystemPath)))
}

// NewWebSocketOrRestReverseProxy creates a reverse proxy for REST or websocket based on url
func NewWebSocketOrRestReverseProxy(u *url.URL, opts *Options, auth hmacauth.HmacAuth) (restProxy http.Handler) {
	u.Path = ""
	proxy := NewReverseProxy(u, opts.FlushInterval)
	if !opts.PassHostHeader {
		setProxyUpstreamHostHeader(proxy, u)
	} else {
		setProxyDirector(proxy)
	}

	// this should give us a wss:// scheme if the url is https:// based.
	var wsProxy *wsutil.ReverseProxy
	if opts.ProxyWebSockets {
		wsScheme := "ws" + strings.TrimPrefix(u.Scheme, "http")
		wsURL := &url.URL{Scheme: wsScheme, Host: u.Host}
		wsProxy = wsutil.NewSingleHostReverseProxy(wsURL)
	}
	return &UpstreamProxy{u.Host, proxy, wsProxy, auth}
}

// NewOAuthProxy creates a new instance of OOuthProxy from the options provided
func NewOAuthProxy(opts *Options, validator func(string) bool) *OAuthProxy {
	serveMux := http.NewServeMux()
	var auth hmacauth.HmacAuth
	if sigData := opts.signatureData; sigData != nil {
		auth = hmacauth.NewHmacAuth(sigData.hash, []byte(sigData.key),
			SignatureHeader, SignatureHeaders)
	}
	for _, u := range opts.proxyURLs {
		path := u.Path
		switch u.Scheme {
		case httpScheme, httpsScheme:
			logger.Printf("mapping path %q => upstream %q", path, u)
			proxy := NewWebSocketOrRestReverseProxy(u, opts, auth)
			serveMux.Handle(path, proxy)

		case "file":
			if u.Fragment != "" {
				path = u.Fragment
			}
			logger.Printf("mapping path %q => file system %q", path, u.Path)
			proxy := NewFileServer(path, u.Path)
			serveMux.Handle(path, &UpstreamProxy{path, proxy, nil, nil})
		default:
			panic(fmt.Sprintf("unknown upstream protocol %s", u.Scheme))
		}
	}
	for _, u := range opts.CompiledRegex {
		logger.Printf("compiled skip-auth-regex => %q", u)
	}

	redirectURL := opts.redirectURL
	if redirectURL.Path == "" {
		redirectURL.Path = fmt.Sprintf("%s/callback", opts.ProxyPrefix)
	}

	logger.Printf("OAuthProxy configured for %s Client ID: %s", opts.provider.Data().ProviderName, opts.ClientID)
	refresh := "disabled"
	if opts.CookieRefresh != time.Duration(0) {
		refresh = fmt.Sprintf("after %s", opts.CookieRefresh)
	}

	logger.Printf("Cookie settings: name:%s secure(https):%v httponly:%v expiry:%s domain:%s path:%s refresh:%s", opts.CookieName, opts.CookieSecure, opts.CookieHTTPOnly, opts.CookieExpire, opts.CookieDomain, opts.CookiePath, refresh)

	var cipher *cookie.Cipher
	if opts.PassAccessToken || opts.SetAuthorization || opts.PassAuthorization || (opts.CookieRefresh != time.Duration(0)) {
		var err error
		cipher, err = cookie.NewCipher(secretBytes(opts.CookieSecret))
		if err != nil {
			logger.Fatal("cookie-secret error: ", err)
		}
	}

	return &OAuthProxy{
		CookieName:     opts.CookieName,
		CSRFCookieName: fmt.Sprintf("%v_%v", opts.CookieName, "csrf"),
		CookieSeed:     opts.CookieSecret,
		CookieDomain:   opts.CookieDomain,
		CookiePath:     opts.CookiePath,
		CookieSecure:   opts.CookieSecure,
		CookieHTTPOnly: opts.CookieHTTPOnly,
		CookieExpire:   opts.CookieExpire,
		CookieRefresh:  opts.CookieRefresh,
		Validator:      validator,

		RobotsPath:        "/robots.txt",
		PingPath:          "/ping",
		SignInPath:        fmt.Sprintf("%s/sign_in", opts.ProxyPrefix),
		SignOutPath:       fmt.Sprintf("%s/sign_out", opts.ProxyPrefix),
		OAuthStartPath:    fmt.Sprintf("%s/start", opts.ProxyPrefix),
		OAuthCallbackPath: fmt.Sprintf("%s/callback", opts.ProxyPrefix),
		AuthOnlyPath:      fmt.Sprintf("%s/auth", opts.ProxyPrefix),

		ProxyPrefix:        opts.ProxyPrefix,
		provider:           opts.provider,
		serveMux:           serveMux,
		redirectURL:        redirectURL,
		whitelistDomains:   opts.WhitelistDomains,
		skipAuthRegex:      opts.SkipAuthRegex,
		skipAuthPreflight:  opts.SkipAuthPreflight,
		compiledRegex:      opts.CompiledRegex,
		SetXAuthRequest:    opts.SetXAuthRequest,
		PassBasicAuth:      opts.PassBasicAuth,
		PassUserHeaders:    opts.PassUserHeaders,
		BasicAuthPassword:  opts.BasicAuthPassword,
		PassAccessToken:    opts.PassAccessToken,
		SetAuthorization:   opts.SetAuthorization,
		PassAuthorization:  opts.PassAuthorization,
		SkipProviderButton: opts.SkipProviderButton,
		CookieCipher:       cipher,
		templates:          loadTemplates(opts.CustomTemplatesDir),
		Footer:             opts.Footer,
	}
}

// GetRedirectURI returns the redirectURL that the upstream OAuth Provider will
// redirect clients to once authenticated
func (p *OAuthProxy) GetRedirectURI(host string) string {
	// default to the request Host if not set
	if p.redirectURL.Host != "" {
		return p.redirectURL.String()
	}
	var u url.URL
	u = *p.redirectURL
	if u.Scheme == "" {
		if p.CookieSecure {
			u.Scheme = httpsScheme
		} else {
			u.Scheme = httpScheme
		}
	}
	u.Host = host
	return u.String()
}

func (p *OAuthProxy) displayCustomLoginForm() bool {
	return p.HtpasswdFile != nil && p.DisplayHtpasswdForm
}

func (p *OAuthProxy) redeemCode(host, code string) (s *providers.SessionState, err error) {
	if code == "" {
		return nil, errors.New("missing code")
	}
	redirectURI := p.GetRedirectURI(host)
	s, err = p.provider.Redeem(redirectURI, code)
	if err != nil {
		return
	}

	if s.Email == "" {
		s.Email, err = p.provider.GetEmailAddress(s)
	}

	if s.User == "" {
		s.User, err = p.provider.GetUserName(s)
		if err != nil && err.Error() == "not implemented" {
			err = nil
		}
	}
	return
}

// MakeSessionCookie creates an http.Cookie containing the authenticated user's
// authentication details
func (p *OAuthProxy) MakeSessionCookie(req *http.Request, value string, expiration time.Duration, now time.Time) []*http.Cookie {
	if value != "" {
		value = cookie.SignedValue(p.CookieSeed, p.CookieName, value, now)
	}
	c := p.makeCookie(req, p.CookieName, value, expiration, now)
	if len(c.Value) > 4096-len(p.CookieName) {
		return splitCookie(c)
	}
	return []*http.Cookie{c}
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

// MakeCSRFCookie creates a cookie for CSRF
func (p *OAuthProxy) MakeCSRFCookie(req *http.Request, value string, expiration time.Duration, now time.Time) *http.Cookie {
	return p.makeCookie(req, p.CSRFCookieName, value, expiration, now)
}

func (p *OAuthProxy) makeCookie(req *http.Request, name string, value string, expiration time.Duration, now time.Time) *http.Cookie {
	if p.CookieDomain != "" {
		domain := req.Host
		if h, _, err := net.SplitHostPort(domain); err == nil {
			domain = h
		}
		if !strings.HasSuffix(domain, p.CookieDomain) {
			logger.Printf("Warning: request host is %q but using configured cookie domain of %q", domain, p.CookieDomain)
		}
	}

	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     p.CookiePath,
		Domain:   p.CookieDomain,
		HttpOnly: p.CookieHTTPOnly,
		Secure:   p.CookieSecure,
		Expires:  now.Add(expiration),
	}
}

// ClearCSRFCookie creates a cookie to unset the CSRF cookie stored in the user's
// session
func (p *OAuthProxy) ClearCSRFCookie(rw http.ResponseWriter, req *http.Request) {
	http.SetCookie(rw, p.MakeCSRFCookie(req, "", time.Hour*-1, time.Now()))
}

// SetCSRFCookie adds a CSRF cookie to the response
func (p *OAuthProxy) SetCSRFCookie(rw http.ResponseWriter, req *http.Request, val string) {
	http.SetCookie(rw, p.MakeCSRFCookie(req, val, p.CookieExpire, time.Now()))
}

// ClearSessionCookie creates a cookie to unset the user's authentication cookie
// stored in the user's session
func (p *OAuthProxy) ClearSessionCookie(rw http.ResponseWriter, req *http.Request) {
	var cookies []*http.Cookie

	// matches CookieName, CookieName_<number>
	var cookieNameRegex = regexp.MustCompile(fmt.Sprintf("^%s(_\\d+)?$", p.CookieName))

	for _, c := range req.Cookies() {
		if cookieNameRegex.MatchString(c.Name) {
			clearCookie := p.makeCookie(req, c.Name, "", time.Hour*-1, time.Now())

			http.SetCookie(rw, clearCookie)
			cookies = append(cookies, clearCookie)
		}
	}

	// ugly hack because default domain changed
	if p.CookieDomain == "" && len(cookies) > 0 {
		clr2 := *cookies[0]
		clr2.Domain = req.Host
		http.SetCookie(rw, &clr2)
	}
}

// SetSessionCookie adds the user's session cookie to the response
func (p *OAuthProxy) SetSessionCookie(rw http.ResponseWriter, req *http.Request, val string) {
	for _, c := range p.MakeSessionCookie(req, val, p.CookieExpire, time.Now()) {
		http.SetCookie(rw, c)
	}
}

// LoadCookiedSession reads the user's authentication details from the request
func (p *OAuthProxy) LoadCookiedSession(req *http.Request) (*providers.SessionState, time.Duration, error) {
	var age time.Duration
	c, err := loadCookie(req, p.CookieName)
	if err != nil {
		// always http.ErrNoCookie
		return nil, age, fmt.Errorf("Cookie %q not present", p.CookieName)
	}
	val, timestamp, ok := cookie.Validate(c, p.CookieSeed, p.CookieExpire)
	if !ok {
		return nil, age, errors.New("Cookie Signature not valid")
	}

	session, err := p.provider.SessionFromCookie(val, p.CookieCipher)
	if err != nil {
		return nil, age, err
	}

	age = time.Now().Truncate(time.Second).Sub(timestamp)
	return session, age, nil
}

// SaveSession creates a new session cookie value and sets this on the response
func (p *OAuthProxy) SaveSession(rw http.ResponseWriter, req *http.Request, s *providers.SessionState) error {
	value, err := p.provider.CookieForSession(s, p.CookieCipher)
	if err != nil {
		return err
	}
	p.SetSessionCookie(rw, req, value)
	return nil
}

// RobotsTxt disallows scraping pages from the OAuthProxy
func (p *OAuthProxy) RobotsTxt(rw http.ResponseWriter) {
	rw.WriteHeader(http.StatusOK)
	fmt.Fprintf(rw, "User-agent: *\nDisallow: /")
}

// PingPage responds 200 OK to requests
func (p *OAuthProxy) PingPage(rw http.ResponseWriter) {
	rw.WriteHeader(http.StatusOK)
	fmt.Fprintf(rw, "OK")
}

// ErrorPage writes an error response
func (p *OAuthProxy) ErrorPage(rw http.ResponseWriter, code int, title string, message string) {
	rw.WriteHeader(code)
	t := struct {
		Title       string
		Message     string
		ProxyPrefix string
	}{
		Title:       fmt.Sprintf("%d %s", code, title),
		Message:     message,
		ProxyPrefix: p.ProxyPrefix,
	}
	p.templates.ExecuteTemplate(rw, "error.html", t)
}

// SignInPage writes the sing in template to the response
func (p *OAuthProxy) SignInPage(rw http.ResponseWriter, req *http.Request, code int) {
	p.ClearSessionCookie(rw, req)
	rw.WriteHeader(code)

	redirecURL := req.URL.RequestURI()
	if req.Header.Get("X-Auth-Request-Redirect") != "" {
		redirecURL = req.Header.Get("X-Auth-Request-Redirect")
	}
	if redirecURL == p.SignInPath {
		redirecURL = "/"
	}

	t := struct {
		ProviderName  string
		SignInMessage string
		CustomLogin   bool
		Redirect      string
		Version       string
		ProxyPrefix   string
		Footer        template.HTML
	}{
		ProviderName:  p.provider.Data().ProviderName,
		SignInMessage: p.SignInMessage,
		CustomLogin:   p.displayCustomLoginForm(),
		Redirect:      redirecURL,
		Version:       VERSION,
		ProxyPrefix:   p.ProxyPrefix,
		Footer:        template.HTML(p.Footer),
	}
	p.templates.ExecuteTemplate(rw, "sign_in.html", t)
}

// ManualSignIn handles basic auth logins to the proxy
func (p *OAuthProxy) ManualSignIn(rw http.ResponseWriter, req *http.Request) (string, bool) {
	if req.Method != "POST" || p.HtpasswdFile == nil {
		return "", false
	}
	user := req.FormValue("username")
	passwd := req.FormValue("password")
	if user == "" {
		return "", false
	}
	// check auth
	if p.HtpasswdFile.Validate(user, passwd) {
		logger.PrintAuthf(user, req, logger.AuthSuccess, "Authenticated via HtpasswdFile")
		return user, true
	}
	logger.PrintAuthf(user, req, logger.AuthFailure, "Invalid authentication via HtpasswdFile")
	return "", false
}

// GetRedirect reads the query parameter to get the URL to redirect clients to
// once authenticated with the OAuthProxy
func (p *OAuthProxy) GetRedirect(req *http.Request) (redirect string, err error) {
	err = req.ParseForm()
	if err != nil {
		return
	}

	redirect = req.Form.Get("rd")
	if !p.IsValidRedirect(redirect) {
		redirect = req.URL.Path
		if strings.HasPrefix(redirect, p.ProxyPrefix) {
			redirect = "/"
		}
	}

	return
}

// IsValidRedirect checks whether the redirect URL is whitelisted
func (p *OAuthProxy) IsValidRedirect(redirect string) bool {
	switch {
	case strings.HasPrefix(redirect, "/") && !strings.HasPrefix(redirect, "//"):
		return true
	case strings.HasPrefix(redirect, "http://") || strings.HasPrefix(redirect, "https://"):
		redirectURL, err := url.Parse(redirect)
		if err != nil {
			return false
		}
		for _, domain := range p.whitelistDomains {
			if (redirectURL.Host == domain) || (strings.HasPrefix(domain, ".") && strings.HasSuffix(redirectURL.Host, domain)) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// IsWhitelistedRequest is used to check if auth should be skipped for this request
func (p *OAuthProxy) IsWhitelistedRequest(req *http.Request) (ok bool) {
	isPreflightRequestAllowed := p.skipAuthPreflight && req.Method == "OPTIONS"
	return isPreflightRequestAllowed || p.IsWhitelistedPath(req.URL.Path)
}

// IsWhitelistedPath is used to check if the request path is allowed without auth
func (p *OAuthProxy) IsWhitelistedPath(path string) (ok bool) {
	for _, u := range p.compiledRegex {
		ok = u.MatchString(path)
		if ok {
			return
		}
	}
	return
}

func getRemoteAddr(req *http.Request) (s string) {
	s = req.RemoteAddr
	if req.Header.Get("X-Real-IP") != "" {
		s += fmt.Sprintf(" (%q)", req.Header.Get("X-Real-IP"))
	}
	return
}

func (p *OAuthProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	switch path := req.URL.Path; {
	case path == p.RobotsPath:
		p.RobotsTxt(rw)
	case path == p.PingPath:
		p.PingPage(rw)
	case p.IsWhitelistedRequest(req):
		p.serveMux.ServeHTTP(rw, req)
	case path == p.SignInPath:
		p.SignIn(rw, req)
	case path == p.SignOutPath:
		p.SignOut(rw, req)
	case path == p.OAuthStartPath:
		p.OAuthStart(rw, req)
	case path == p.OAuthCallbackPath:
		p.OAuthCallback(rw, req)
	case path == p.AuthOnlyPath:
		p.AuthenticateOnly(rw, req)
	default:
		p.Proxy(rw, req)
	}
}

// SignIn serves a page prompting users to sign in
func (p *OAuthProxy) SignIn(rw http.ResponseWriter, req *http.Request) {
	redirect, err := p.GetRedirect(req)
	if err != nil {
		logger.Printf("Error obtaining redirect: %s", err.Error())
		p.ErrorPage(rw, 500, "Internal Error", err.Error())
		return
	}

	user, ok := p.ManualSignIn(rw, req)
	if ok {
		session := &providers.SessionState{User: user}
		p.SaveSession(rw, req, session)
		http.Redirect(rw, req, redirect, 302)
	} else {
		if p.SkipProviderButton {
			p.OAuthStart(rw, req)
		} else {
			p.SignInPage(rw, req, http.StatusOK)
		}
	}
}

// SignOut sends a response to clear the authentication cookie
func (p *OAuthProxy) SignOut(rw http.ResponseWriter, req *http.Request) {
	p.ClearSessionCookie(rw, req)
	http.Redirect(rw, req, "/", 302)
}

// OAuthStart starts the OAuth2 authentication flow
func (p *OAuthProxy) OAuthStart(rw http.ResponseWriter, req *http.Request) {
	nonce, err := cookie.Nonce()
	if err != nil {
		logger.Printf("Error obtaining nonce: %s", err.Error())
		p.ErrorPage(rw, 500, "Internal Error", err.Error())
		return
	}
	p.SetCSRFCookie(rw, req, nonce)
	redirect, err := p.GetRedirect(req)
	if err != nil {
		logger.Printf("Error obtaining redirect: %s", err.Error())
		p.ErrorPage(rw, 500, "Internal Error", err.Error())
		return
	}
	redirectURI := p.GetRedirectURI(req.Host)
	http.Redirect(rw, req, p.provider.GetLoginURL(redirectURI, fmt.Sprintf("%v:%v", nonce, redirect)), 302)
}

// OAuthCallback is the OAuth2 authentication flow callback that finishes the
// OAuth2 authentication flow
func (p *OAuthProxy) OAuthCallback(rw http.ResponseWriter, req *http.Request) {
	remoteAddr := getRemoteAddr(req)

	// finish the oauth cycle
	err := req.ParseForm()
	if err != nil {
		logger.Printf("Error while parsing OAuth2 callback: %s" + err.Error())
		p.ErrorPage(rw, 500, "Internal Error", err.Error())
		return
	}
	errorString := req.Form.Get("error")
	if errorString != "" {
		logger.Printf("Error while parsing OAuth2 callback: %s ", errorString)
		p.ErrorPage(rw, 403, "Permission Denied", errorString)
		return
	}

	session, err := p.redeemCode(req.Host, req.Form.Get("code"))
	if err != nil {
		logger.Printf("Error redeeming code during OAuth2 callback: %s ", err.Error())
		p.ErrorPage(rw, 500, "Internal Error", "Internal Error")
		return
	}

	s := strings.SplitN(req.Form.Get("state"), ":", 2)
	if len(s) != 2 {
		logger.Printf("Error while parsing OAuth2 state: invalid length")
		p.ErrorPage(rw, 500, "Internal Error", "Invalid State")
		return
	}
	nonce := s[0]
	redirect := s[1]
	c, err := req.Cookie(p.CSRFCookieName)
	if err != nil {
		logger.PrintAuthf(session.Email, req, logger.AuthFailure, "Invalid authentication via OAuth2: unable too obtain CSRF cookie")
		p.ErrorPage(rw, 403, "Permission Denied", err.Error())
		return
	}
	p.ClearCSRFCookie(rw, req)
	if c.Value != nonce {
		logger.PrintAuthf(session.Email, req, logger.AuthFailure, "Invalid authentication via OAuth2: csrf token mismatch, potential attack")
		p.ErrorPage(rw, 403, "Permission Denied", "csrf failed")
		return
	}

	if !p.IsValidRedirect(redirect) {
		redirect = "/"
	}

	// set cookie, or deny
	if p.Validator(session.Email) && p.provider.ValidateGroup(session.Email) {
		logger.PrintAuthf(session.Email, req, logger.AuthSuccess, "Authenticated via OAuth2: %s", session)
		err := p.SaveSession(rw, req, session)
		if err != nil {
			logger.Printf("%s %s", remoteAddr, err)
			p.ErrorPage(rw, 500, "Internal Error", "Internal Error")
			return
		}
		http.Redirect(rw, req, redirect, 302)
	} else {
		logger.PrintAuthf(session.Email, req, logger.AuthSuccess, "Invalid authentication via OAuth2: unauthorized")
		p.ErrorPage(rw, 403, "Permission Denied", "Invalid Account")
	}
}

// AuthenticateOnly checks whether the user is currently logged in
func (p *OAuthProxy) AuthenticateOnly(rw http.ResponseWriter, req *http.Request) {
	status := p.Authenticate(rw, req)
	if status == http.StatusAccepted {
		rw.WriteHeader(http.StatusAccepted)
	} else {
		http.Error(rw, "unauthorized request", http.StatusUnauthorized)
	}
}

// Proxy proxies the user request if the user is authenticated else it prompts
// them to authenticate
func (p *OAuthProxy) Proxy(rw http.ResponseWriter, req *http.Request) {
	status := p.Authenticate(rw, req)
	if status == http.StatusInternalServerError {
		p.ErrorPage(rw, http.StatusInternalServerError,
			"Internal Error", "Internal Error")
	} else if status == http.StatusForbidden {
		if p.SkipProviderButton {
			p.OAuthStart(rw, req)
		} else {
			p.SignInPage(rw, req, http.StatusForbidden)
		}
	} else if status == http.StatusUnauthorized {
		p.ErrorJSON(rw, status)
	} else {
		p.serveMux.ServeHTTP(rw, req)
	}
}

// Authenticate checks whether a user is authenticated
func (p *OAuthProxy) Authenticate(rw http.ResponseWriter, req *http.Request) int {
	var saveSession, clearSession, revalidated bool
	remoteAddr := getRemoteAddr(req)

	session, sessionAge, err := p.LoadCookiedSession(req)
	if err != nil {
		logger.Printf("Error loading cookied session: %s", err)
	}
	if session != nil && sessionAge > p.CookieRefresh && p.CookieRefresh != time.Duration(0) {
		logger.Printf("Refreshing %s old session cookie for %s (refresh after %s)", sessionAge, session, p.CookieRefresh)
		saveSession = true
	}

	var ok bool
	if ok, err = p.provider.RefreshSessionIfNeeded(session); err != nil {
		logger.Printf("%s removing session. error refreshing access token %s %s", remoteAddr, err, session)
		clearSession = true
		session = nil
	} else if ok {
		saveSession = true
		revalidated = true
	}

	if session != nil && session.IsExpired() {
		logger.Printf("Removing session: token expired %s", session)
		session = nil
		saveSession = false
		clearSession = true
	}

	if saveSession && !revalidated && session != nil && session.AccessToken != "" {
		if !p.provider.ValidateSessionState(session) {
			logger.Printf("Removing session: error validating %s", session)
			saveSession = false
			session = nil
			clearSession = true
		}
	}

	if session != nil && session.Email != "" && !p.Validator(session.Email) {
		logger.Printf(session.Email, req, logger.AuthFailure, "Invalid authentication via session: removing session %s", session)
		session = nil
		saveSession = false
		clearSession = true
	}

	if saveSession && session != nil {
		err = p.SaveSession(rw, req, session)
		if err != nil {
			logger.PrintAuthf(session.Email, req, logger.AuthError, "Save session error %s", err)
			return http.StatusInternalServerError
		}
	}

	if clearSession {
		p.ClearSessionCookie(rw, req)
	}

	if session == nil {
		session, err = p.CheckBasicAuth(req)
		if err != nil {
			logger.Printf("Error during basic auth validation: %s", err)
		}
	}

	if session == nil {
		// Check if is an ajax request and return unauthorized to avoid a redirect
		// to the login page
		if p.isAjax(req) {
			return http.StatusUnauthorized
		}
		return http.StatusForbidden
	}

	// At this point, the user is authenticated. proxy normally
	if p.PassBasicAuth {
		req.SetBasicAuth(session.User, p.BasicAuthPassword)
		req.Header["X-Forwarded-User"] = []string{session.User}
		if session.Email != "" {
			req.Header["X-Forwarded-Email"] = []string{session.Email}
		}
	}
	if p.PassUserHeaders {
		req.Header["X-Forwarded-User"] = []string{session.User}
		if session.Email != "" {
			req.Header["X-Forwarded-Email"] = []string{session.Email}
		}
	}
	if p.SetXAuthRequest {
		rw.Header().Set("X-Auth-Request-User", session.User)
		if session.Email != "" {
			rw.Header().Set("X-Auth-Request-Email", session.Email)
		}
		if p.PassAccessToken && session.AccessToken != "" {
			rw.Header().Set("X-Auth-Request-Access-Token", session.AccessToken)
		}
	}
	if p.PassAccessToken && session.AccessToken != "" {
		req.Header["X-Forwarded-Access-Token"] = []string{session.AccessToken}
	}
	if p.PassAuthorization && session.IDToken != "" {
		req.Header["Authorization"] = []string{fmt.Sprintf("Bearer %s", session.IDToken)}
	}
	if p.SetAuthorization && session.IDToken != "" {
		rw.Header().Set("Authorization", fmt.Sprintf("Bearer %s", session.IDToken))
	}
	if session.Email == "" {
		rw.Header().Set("GAP-Auth", session.User)
	} else {
		rw.Header().Set("GAP-Auth", session.Email)
	}
	return http.StatusAccepted
}

// CheckBasicAuth checks the requests Authorization header for basic auth
// credentials and authenticates these against the proxies HtpasswdFile
func (p *OAuthProxy) CheckBasicAuth(req *http.Request) (*providers.SessionState, error) {
	if p.HtpasswdFile == nil {
		return nil, nil
	}
	auth := req.Header.Get("Authorization")
	if auth == "" {
		return nil, nil
	}
	s := strings.SplitN(auth, " ", 2)
	if len(s) != 2 || s[0] != "Basic" {
		return nil, fmt.Errorf("invalid Authorization header %s", req.Header.Get("Authorization"))
	}
	b, err := b64.StdEncoding.DecodeString(s[1])
	if err != nil {
		return nil, err
	}
	pair := strings.SplitN(string(b), ":", 2)
	if len(pair) != 2 {
		return nil, fmt.Errorf("invalid format %s", b)
	}
	if p.HtpasswdFile.Validate(pair[0], pair[1]) {
		logger.PrintAuthf(pair[0], req, logger.AuthSuccess, "Authenticated via basic auth and HTpasswd File")
		return &providers.SessionState{User: pair[0]}, nil
	}
	logger.PrintAuthf(pair[0], req, logger.AuthFailure, "Invalid authentication via basic auth: not in Htpasswd File")
	return nil, nil
}

// isAjax checks if a request is an ajax request
func (p *OAuthProxy) isAjax(req *http.Request) bool {
	acceptValues, ok := req.Header["accept"]
	if !ok {
		acceptValues = req.Header["Accept"]
	}
	const ajaxReq = applicationJSON
	for _, v := range acceptValues {
		if v == ajaxReq {
			return true
		}
	}
	return false
}

// ErrorJSON returns the error code witht an application/json mime type
func (p *OAuthProxy) ErrorJSON(rw http.ResponseWriter, code int) {
	rw.Header().Set("Content-Type", applicationJSON)
	rw.WriteHeader(code)
}
