package main

import (
	"context"
	"crypto/tls"
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/mbland/hmacauth"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/cookies"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/encryption"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/providers"
	"github.com/yhat/wsutil"
)

const (
	// SignatureHeader is the name of the request header containing the GAP Signature
	// Part of hmacauth
	SignatureHeader = "GAP-Signature"

	httpScheme  = "http"
	httpsScheme = "https"

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
	"X-Forwarded-Preferred-User",
	"X-Forwarded-Access-Token",
	"Cookie",
	"Gap-Auth",
}

var (
	// ErrNeedsLogin means the user should be redirected to the login page
	ErrNeedsLogin = errors.New("redirect to login page")
)

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
	CookieSameSite string
	Validator      func(string) bool

	RobotsPath        string
	PingPath          string
	SignInPath        string
	SignOutPath       string
	OAuthStartPath    string
	OAuthCallbackPath string
	AuthOnlyPath      string
	UserInfoPath      string

	redirectURL          *url.URL // the url to receive requests at
	whitelistDomains     []string
	provider             providers.Provider
	providerNameOverride string
	sessionStore         sessionsapi.SessionStore
	ProxyPrefix          string
	SignInMessage        string
	HtpasswdFile         *HtpasswdFile
	DisplayHtpasswdForm  bool
	serveMux             http.Handler
	SetXAuthRequest      bool
	PassBasicAuth        bool
	SkipProviderButton   bool
	PassUserHeaders      bool
	BasicAuthPassword    string
	PassAccessToken      bool
	SetAuthorization     bool
	PassAuthorization    bool
	PreferEmailToUser    bool
	skipAuthRegex        []string
	skipAuthPreflight    bool
	skipJwtBearerTokens  bool
	jwtBearerVerifiers   []*oidc.IDTokenVerifier
	compiledRegex        []*regexp.Regexp
	templates            *template.Template
	Banner               string
	Footer               string
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
	if u.wsHandler != nil && strings.EqualFold(r.Header.Get("Connection"), "upgrade") && r.Header.Get("Upgrade") == "websocket" {
		u.wsHandler.ServeHTTP(w, r)
	} else {
		u.handler.ServeHTTP(w, r)
	}

}

// NewDefaultReverseProxy creates a reverse proxy using the default path mapping rules (i.e.
// the muxPath will be whatever the target URL's path is). So, for example,
// "http://foo/path/" will mux to the "/path/" when determining which handler
// to call.
//
// To create a customized path mapping use NewReverseProxy()
func NewDefaultReverseProxy(target *url.URL, opts *Options) (proxy *httputil.ReverseProxy) {
	return NewReverseProxy(target, target.EscapedPath(), opts)
}

// NewReverseProxy creates a new reverse proxy for proxying requests to upstream
// servers. It has to tweak the default httputil.NewSingleHostReverseProxy()
// "director" callback because:
//
//  - There are some slightly different semantics we want for path combination.
//    By default, an upstream "http://upstream/upath/" binds to "/upath/" for the
//    serveMux which results in:
//
//         "http://proxy/upath/file.html" => "http://upstream/upath/file.html"
//
//    But the default path appending behavior of httputil's version would cause
//    extra path info being injected (e.g. "http://upstream/upath/upath/file.html")
//    resulting in incorrect upstream URLs. Further, we'd like to remap some
//    upstream locations by explicitly providing a different "base", for example:
//
//         "http://proxy/file.html" => "http://upstream/upath/file.html"
//
//    Can be accomplished by specifying "http://upstream/upath/#/" and it will
//    use the fragment as the `muxPath` (similar to how local file remapping works).
//
//  - Also, there (at the time of writing) is a bug with how it handles escaped Paths:
//      https://github.com/golang/go/pull/36378/files
//
//  - However, we make sure to retain the query param merging, as it's important
//    in situations where the upstream requires an authentication token for example.
//
func NewReverseProxy(target *url.URL, muxPath string, opts *Options) (proxy *httputil.ReverseProxy) {

	passRequestHost := opts.PassHostHeader
	proxy = httputil.NewSingleHostReverseProxy(target)

	primeDirector := proxy.Director

	proxy.Director = func(req *http.Request) {
		// Save the original path (and rawpath) to work around the bug with
		// escaped slashes in older versions of Go.
		origPath, origRawPath := req.URL.Path, req.URL.RawPath

		// Wrap the default httputil implementation as it does some useful
		// things like query string merging and updating the User Agent if
		// necessary (also lets us get fixes made to Go later on).
		primeDirector(req)

		if !passRequestHost {
			// Make sure this matches the target if we're not explicitly
			// sending the request's Host instead.
			req.Host = target.Host
		}

		// Take request's "/foo/file.html" and strip the muxPath off the
		// front. We know it exists on the path since that's how this
		// handler got called in the first place (via proxy's serveMux
		// path matching). If muxPath is "/foo/" we want "/file.html"
		// (note the slash is retained). Note: this replaces the possibly
		// incorrect path calculated in the default implementation.

		if origRawPath != "" {
			// If this is not empty, then the path had some escaping done,
			// and in order to maintain its pairity with the "non-Raw"
			// version, we have to trim that one so it matches. As the
			// semantics are that if RawPath doesn't decode into exactly
			// the Path value, it's ignored.
			req.URL.RawPath = strings.TrimPrefix(origRawPath, muxPath)
			if unescapedMuxPath, err := url.PathUnescape(muxPath); err != nil {
				req.URL.Path = strings.TrimPrefix(origPath, unescapedMuxPath)
			} else {
				// This would only happen if muxPath was incorrectly passed
				// to us (such a malformed manual path remapping). Not really
				// much we can do... I'm not sure what HTTP servers are
				// supposed to do in this case.
				req.URL.Path = strings.TrimPrefix(origPath, muxPath)
			}
		} else {
			// With no escaping, there's less to worry about.
			req.URL.Path = strings.TrimPrefix(origPath, muxPath)
		}

		if req.URL.Path == "" {
			// Make sure we don't inject an extra trailing '/' if
			// the path has been completely removed after trimming
			req.URL.Path = target.Path
			req.URL.RawPath = target.RawPath
		} else {
			req.URL.Path, req.URL.RawPath = joinURLPath(target, req.URL)
		}
	}

	proxy.FlushInterval = opts.FlushInterval
	if opts.SSLUpstreamInsecureSkipVerify {
		proxy.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	return proxy
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func joinURLPath(a, b *url.URL) (path, rawpath string) {
	if a.RawPath == "" && b.RawPath == "" {
		return singleJoiningSlash(a.Path, b.Path), ""
	}
	// Same as singleJoiningSlash, but uses EscapedPath to determine
	// whether a slash should be added
	apath := a.EscapedPath()
	bpath := b.EscapedPath()

	aslash := strings.HasSuffix(apath, "/")
	bslash := strings.HasPrefix(bpath, "/")

	switch {
	case aslash && bslash:
		return a.Path + b.Path[1:], apath + bpath[1:]
	case !aslash && !bslash:
		return a.Path + "/" + b.Path, apath + "/" + bpath
	}
	return a.Path + b.Path, apath + bpath
}

// NewFileServer creates a http.Handler to serve files from the filesystem
func NewFileServer(path string, filesystemPath string) (proxy http.Handler) {
	return http.StripPrefix(path, http.FileServer(http.Dir(filesystemPath)))
}

// NewWebSocketOrRestReverseProxy creates a reverse proxy for REST or websocket based on url
func NewWebSocketOrRestReverseProxy(u *url.URL, muxPath string, opts *Options, auth hmacauth.HmacAuth) http.Handler {
	proxy := NewReverseProxy(u, muxPath, opts)

	// this should give us a wss:// scheme if the url is https:// based.
	var wsProxy *wsutil.ReverseProxy
	if opts.ProxyWebSockets {
		wsScheme := "ws" + strings.TrimPrefix(u.Scheme, "http")
		wsURL := &url.URL{Scheme: wsScheme, Host: u.Host}
		wsProxy = wsutil.NewSingleHostReverseProxy(wsURL)
	}
	return &UpstreamProxy{
		upstream:  u.Host,
		handler:   proxy,
		wsHandler: wsProxy,
		auth:      auth,
	}
}

func checkMuxPath(path string) {
	if strings.Contains(path, "%2f") || strings.Contains(path, "%2F") {
		// http.NewServeMux() doesn't deal with escaped paths properly when figuring out which
		// handler to invoke since it uses url.URL.Path under the hood. i.e. it unescapes it and
		// tries to match that instead.
		// TODO: Investigate using http://github.com/gorilla/mux instead?
		// TODO: If this is fixed, look for the currently t.Skip()'d tests in oauthproxy_test.go and re-enable them
		logger.Printf("warning: mapping paths with escaped slashes are not currently supported: %s", path)
	}
}

// NewOAuthProxy creates a new instance of OAuthProxy from the options provided
func NewOAuthProxy(opts *Options, validator func(string) bool) *OAuthProxy {
	serveMux := http.NewServeMux()
	var auth hmacauth.HmacAuth
	if sigData := opts.signatureData; sigData != nil {
		auth = hmacauth.NewHmacAuth(sigData.hash, []byte(sigData.key),
			SignatureHeader, SignatureHeaders)
	}
	for _, u := range opts.proxyURLs {
		path := u.EscapedPath()
		host := u.Host
		switch u.Scheme {
		case httpScheme, httpsScheme:
			if u.Fragment != "" {
				path = u.Fragment
			}
			logger.Printf("mapping path %q => upstream %q", path, u)
			proxy := NewWebSocketOrRestReverseProxy(u, path, opts, auth)
			checkMuxPath(path)
			serveMux.Handle(path, proxy)
		case "static":
			responseCode, err := strconv.Atoi(host)
			if err != nil {
				logger.Printf("unable to convert %q to int, use default \"200\"", host)
				responseCode = 200
			}

			checkMuxPath(path)
			serveMux.HandleFunc(path, func(rw http.ResponseWriter, req *http.Request) {
				rw.WriteHeader(responseCode)
				fmt.Fprintf(rw, "Authenticated")
			})
		case "file":
			if u.Fragment != "" {
				path = u.Fragment
			}
			logger.Printf("mapping path %q => file system %q", path, u.Path)
			proxy := NewFileServer(path, u.Path)
			uProxy := UpstreamProxy{
				upstream:  path,
				handler:   proxy,
				wsHandler: nil,
				auth:      nil,
			}
			checkMuxPath(path)
			serveMux.Handle(path, &uProxy)
		default:
			panic(fmt.Sprintf("unknown upstream protocol %s", u.Scheme))
		}
	}
	for _, u := range opts.CompiledRegex {
		logger.Printf("compiled skip-auth-regex => %q", u)
	}

	if opts.SkipJwtBearerTokens {
		logger.Printf("Skipping JWT tokens from configured OIDC issuer: %q", opts.OIDCIssuerURL)
		for _, issuer := range opts.ExtraJwtIssuers {
			logger.Printf("Skipping JWT tokens from extra JWT issuer: %q", issuer)
		}
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

	logger.Printf("Cookie settings: name:%s secure(https):%v httponly:%v expiry:%s domain:%s path:%s samesite:%s refresh:%s", opts.CookieName, opts.CookieSecure, opts.CookieHTTPOnly, opts.CookieExpire, opts.CookieDomain, opts.CookiePath, opts.CookieSameSite, refresh)

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
		CookieSameSite: opts.CookieSameSite,
		Validator:      validator,

		RobotsPath:        "/robots.txt",
		PingPath:          opts.PingPath,
		SignInPath:        fmt.Sprintf("%s/sign_in", opts.ProxyPrefix),
		SignOutPath:       fmt.Sprintf("%s/sign_out", opts.ProxyPrefix),
		OAuthStartPath:    fmt.Sprintf("%s/start", opts.ProxyPrefix),
		OAuthCallbackPath: fmt.Sprintf("%s/callback", opts.ProxyPrefix),
		AuthOnlyPath:      fmt.Sprintf("%s/auth", opts.ProxyPrefix),
		UserInfoPath:      fmt.Sprintf("%s/userinfo", opts.ProxyPrefix),

		ProxyPrefix:          opts.ProxyPrefix,
		provider:             opts.provider,
		providerNameOverride: opts.ProviderName,
		sessionStore:         opts.sessionStore,
		serveMux:             serveMux,
		redirectURL:          redirectURL,
		whitelistDomains:     opts.WhitelistDomains,
		skipAuthRegex:        opts.SkipAuthRegex,
		skipAuthPreflight:    opts.SkipAuthPreflight,
		skipJwtBearerTokens:  opts.SkipJwtBearerTokens,
		jwtBearerVerifiers:   opts.jwtBearerVerifiers,
		compiledRegex:        opts.CompiledRegex,
		SetXAuthRequest:      opts.SetXAuthRequest,
		PassBasicAuth:        opts.PassBasicAuth,
		PassUserHeaders:      opts.PassUserHeaders,
		BasicAuthPassword:    opts.BasicAuthPassword,
		PassAccessToken:      opts.PassAccessToken,
		SetAuthorization:     opts.SetAuthorization,
		PassAuthorization:    opts.PassAuthorization,
		PreferEmailToUser:    opts.PreferEmailToUser,
		SkipProviderButton:   opts.SkipProviderButton,
		templates:            loadTemplates(opts.CustomTemplatesDir),
		Banner:               opts.Banner,
		Footer:               opts.Footer,
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

func (p *OAuthProxy) redeemCode(host, code string) (s *sessionsapi.SessionState, err error) {
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

	if s.PreferredUsername == "" {
		s.PreferredUsername, err = p.provider.GetPreferredUsername(s)
		if err != nil && err.Error() == "not implemented" {
			err = nil
		}
	}

	if s.User == "" {
		s.User, err = p.provider.GetUserName(s)
		if err != nil && err.Error() == "not implemented" {
			err = nil
		}
	}
	return
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
		SameSite: cookies.ParseSameSite(p.CookieSameSite),
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
func (p *OAuthProxy) ClearSessionCookie(rw http.ResponseWriter, req *http.Request) error {
	return p.sessionStore.Clear(rw, req)
}

// LoadCookiedSession reads the user's authentication details from the request
func (p *OAuthProxy) LoadCookiedSession(req *http.Request) (*sessionsapi.SessionState, error) {
	return p.sessionStore.Load(req)
}

// SaveSession creates a new session cookie value and sets this on the response
func (p *OAuthProxy) SaveSession(rw http.ResponseWriter, req *http.Request, s *sessionsapi.SessionState) error {
	return p.sessionStore.Save(rw, req, s)
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

	redirectURL, err := p.GetRedirect(req)
	if err != nil {
		logger.Printf("Error obtaining redirect: %s", err.Error())
		p.ErrorPage(rw, 500, "Internal Error", err.Error())
		return
	}

	if redirectURL == p.SignInPath {
		redirectURL = "/"
	}

	t := struct {
		ProviderName  string
		SignInMessage template.HTML
		CustomLogin   bool
		Redirect      string
		Version       string
		ProxyPrefix   string
		Footer        template.HTML
	}{
		ProviderName:  p.provider.Data().ProviderName,
		SignInMessage: template.HTML(p.SignInMessage),
		CustomLogin:   p.displayCustomLoginForm(),
		Redirect:      redirectURL,
		Version:       VERSION,
		ProxyPrefix:   p.ProxyPrefix,
		Footer:        template.HTML(p.Footer),
	}
	if p.providerNameOverride != "" {
		t.ProviderName = p.providerNameOverride
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

	redirect = req.Header.Get("X-Auth-Request-Redirect")
	if req.Form.Get("rd") != "" {
		redirect = req.Form.Get("rd")
	}
	if !p.IsValidRedirect(redirect) {
		redirect = req.URL.Path
		if strings.HasPrefix(redirect, p.ProxyPrefix) {
			redirect = "/"
		}
	}

	return
}

// splitHostPort separates host and port. If the port is not valid, it returns
// the entire input as host, and it doesn't check the validity of the host.
// Unlike net.SplitHostPort, but per RFC 3986, it requires ports to be numeric.
// *** taken from net/url, modified validOptionalPort() to accept ":*"
func splitHostPort(hostport string) (host, port string) {
	host = hostport

	colon := strings.LastIndexByte(host, ':')
	if colon != -1 && validOptionalPort(host[colon:]) {
		host, port = host[:colon], host[colon+1:]
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}

	return
}

// validOptionalPort reports whether port is either an empty string
// or matches /^:\d*$/
// *** taken from net/url, modified to accept ":*"
func validOptionalPort(port string) bool {
	if port == "" || port == ":*" {
		return true
	}
	if port[0] != ':' {
		return false
	}
	for _, b := range port[1:] {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

// IsValidRedirect checks whether the redirect URL is whitelisted
func (p *OAuthProxy) IsValidRedirect(redirect string) bool {
	switch {
	case strings.HasPrefix(redirect, "/") && !strings.HasPrefix(redirect, "//") && !strings.HasPrefix(redirect, "/\\"):
		return true
	case strings.HasPrefix(redirect, "http://") || strings.HasPrefix(redirect, "https://"):
		redirectURL, err := url.Parse(redirect)
		if err != nil {
			logger.Printf("Rejecting invalid redirect %q: scheme unsupported or missing", redirect)
			return false
		}
		redirectHostname := redirectURL.Hostname()

		for _, domain := range p.whitelistDomains {
			domainHostname, domainPort := splitHostPort(strings.TrimLeft(domain, "."))
			if domainHostname == "" {
				continue
			}

			if (redirectHostname == domainHostname) || (strings.HasPrefix(domain, ".") && strings.HasSuffix(redirectHostname, domainHostname)) {
				// the domain names match, now validate the ports
				// if the whitelisted domain's port is '*', allow all ports
				// if the whitelisted domain contains a specific port, only allow that port
				// if the whitelisted domain doesn't contain a port at all, only allow empty redirect ports ie http and https
				redirectPort := redirectURL.Port()
				if (domainPort == "*") ||
					(domainPort == redirectPort) ||
					(domainPort == "" && redirectPort == "") {
					return true
				}
			}
		}

		logger.Printf("Rejecting invalid redirect %q: domain / port not in whitelist", redirect)
		return false
	default:
		logger.Printf("Rejecting invalid redirect %q: not an absolute or relative URL", redirect)
		return false
	}
}

// IsWhitelistedRequest is used to check if auth should be skipped for this request
func (p *OAuthProxy) IsWhitelistedRequest(req *http.Request) bool {
	isPreflightRequestAllowed := p.skipAuthPreflight && req.Method == "OPTIONS"
	return isPreflightRequestAllowed || p.IsWhitelistedPath(req.URL.Path)
}

// IsWhitelistedPath is used to check if the request path is allowed without auth
func (p *OAuthProxy) IsWhitelistedPath(path string) bool {
	for _, u := range p.compiledRegex {
		if u.MatchString(path) {
			return true
		}
	}
	return false
}

func getRemoteAddr(req *http.Request) (s string) {
	s = req.RemoteAddr
	if req.Header.Get("X-Real-IP") != "" {
		s += fmt.Sprintf(" (%q)", req.Header.Get("X-Real-IP"))
	}
	return
}

func (p *OAuthProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	switch path := req.URL.EscapedPath(); {
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
	case path == p.UserInfoPath:
		p.UserInfo(rw, req)
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
		session := &sessionsapi.SessionState{User: user}
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

//UserInfo endpoint outputs session email and preferred username in JSON format
func (p *OAuthProxy) UserInfo(rw http.ResponseWriter, req *http.Request) {

	session, err := p.getAuthenticatedSession(rw, req)
	if err != nil {
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	userInfo := struct {
		Email             string `json:"email"`
		PreferredUsername string `json:"preferredUsername,omitempty"`
	}{
		Email:             session.Email,
		PreferredUsername: session.PreferredUsername,
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	json.NewEncoder(rw).Encode(userInfo)
}

// SignOut sends a response to clear the authentication cookie
func (p *OAuthProxy) SignOut(rw http.ResponseWriter, req *http.Request) {
	redirect, err := p.GetRedirect(req)
	if err != nil {
		logger.Printf("Error obtaining redirect: %s", err.Error())
		p.ErrorPage(rw, 500, "Internal Error", err.Error())
		return
	}
	p.ClearSessionCookie(rw, req)
	http.Redirect(rw, req, redirect, 302)
}

// OAuthStart starts the OAuth2 authentication flow
func (p *OAuthProxy) OAuthStart(rw http.ResponseWriter, req *http.Request) {
	nonce, err := encryption.Nonce()
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
		logger.PrintAuthf(session.Email, req, logger.AuthFailure, "Invalid authentication via OAuth2: unauthorized")
		p.ErrorPage(rw, 403, "Permission Denied", "Invalid Account")
	}
}

// AuthenticateOnly checks whether the user is currently logged in
func (p *OAuthProxy) AuthenticateOnly(rw http.ResponseWriter, req *http.Request) {
	session, err := p.getAuthenticatedSession(rw, req)
	if err != nil {
		http.Error(rw, "unauthorized request", http.StatusUnauthorized)
		return
	}

	// we are authenticated
	p.addHeadersForProxying(rw, req, session)
	rw.WriteHeader(http.StatusAccepted)
}

// Proxy proxies the user request if the user is authenticated else it prompts
// them to authenticate
func (p *OAuthProxy) Proxy(rw http.ResponseWriter, req *http.Request) {
	session, err := p.getAuthenticatedSession(rw, req)
	switch err {
	case nil:
		// we are authenticated
		p.addHeadersForProxying(rw, req, session)
		p.serveMux.ServeHTTP(rw, req)

	case ErrNeedsLogin:
		// we need to send the user to a login screen
		if isAjax(req) {
			// no point redirecting an AJAX request
			p.ErrorJSON(rw, http.StatusUnauthorized)
			return
		}

		if p.SkipProviderButton {
			p.OAuthStart(rw, req)
		} else {
			p.SignInPage(rw, req, http.StatusForbidden)
		}

	default:
		// unknown error
		logger.Printf("Unexpected internal error: %s", err)
		p.ErrorPage(rw, http.StatusInternalServerError,
			"Internal Error", "Internal Error")
	}

}

// getAuthenticatedSession checks whether a user is authenticated and returns a session object and nil error if so
// Returns nil, ErrNeedsLogin if user needs to login.
// Set-Cookie headers may be set on the response as a side-effect of calling this method.
func (p *OAuthProxy) getAuthenticatedSession(rw http.ResponseWriter, req *http.Request) (*sessionsapi.SessionState, error) {
	var session *sessionsapi.SessionState
	var err error
	var saveSession, clearSession, revalidated bool

	if p.skipJwtBearerTokens && req.Header.Get("Authorization") != "" {
		session, err = p.GetJwtSession(req)
		if err != nil {
			logger.Printf("Error retrieving session from token in Authorization header: %s", err)
		}
		if session != nil {
			saveSession = false
		}
	}

	remoteAddr := getRemoteAddr(req)
	if session == nil {
		session, err = p.LoadCookiedSession(req)
		if err != nil {
			logger.Printf("Error loading cookied session: %s", err)
		}

		if session != nil {
			if session.Age() > p.CookieRefresh && p.CookieRefresh != time.Duration(0) {
				logger.Printf("Refreshing %s old session cookie for %s (refresh after %s)", session.Age(), session, p.CookieRefresh)
				saveSession = true
			}

			if ok, err := p.provider.RefreshSessionIfNeeded(session); err != nil {
				logger.Printf("%s removing session. error refreshing access token %s %s", remoteAddr, err, session)
				clearSession = true
				session = nil
			} else if ok {
				saveSession = true
				revalidated = true
			}
		}
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
			return nil, err
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
		return nil, ErrNeedsLogin
	}

	return session, nil
}

// addHeadersForProxying adds the appropriate headers the request / response for proxying
func (p *OAuthProxy) addHeadersForProxying(rw http.ResponseWriter, req *http.Request, session *sessionsapi.SessionState) {
	if p.PassBasicAuth {
		if p.PreferEmailToUser && session.Email != "" {
			req.SetBasicAuth(session.Email, p.BasicAuthPassword)
			req.Header["X-Forwarded-User"] = []string{session.Email}
			req.Header.Del("X-Forwarded-Email")
		} else {
			req.SetBasicAuth(session.User, p.BasicAuthPassword)
			req.Header["X-Forwarded-User"] = []string{session.User}
			if session.Email != "" {
				req.Header["X-Forwarded-Email"] = []string{session.Email}
			} else {
				req.Header.Del("X-Forwarded-Email")
			}
		}
		if session.PreferredUsername != "" {
			req.Header["X-Forwarded-Preferred-Username"] = []string{session.PreferredUsername}
		} else {
			req.Header.Del("X-Forwarded-Preferred-Username")
		}
	}

	if p.PassUserHeaders {
		if p.PreferEmailToUser && session.Email != "" {
			req.Header["X-Forwarded-User"] = []string{session.Email}
			req.Header.Del("X-Forwarded-Email")
		} else {
			req.Header["X-Forwarded-User"] = []string{session.User}
			if session.Email != "" {
				req.Header["X-Forwarded-Email"] = []string{session.Email}
			} else {
				req.Header.Del("X-Forwarded-Email")
			}
		}

		if session.PreferredUsername != "" {
			req.Header["X-Forwarded-Preferred-Username"] = []string{session.PreferredUsername}
		} else {
			req.Header.Del("X-Forwarded-Preferred-Username")
		}
	}

	if p.SetXAuthRequest {
		rw.Header().Set("X-Auth-Request-User", session.User)
		if session.Email != "" {
			rw.Header().Set("X-Auth-Request-Email", session.Email)
		} else {
			rw.Header().Del("X-Auth-Request-Email")
		}
		if session.PreferredUsername != "" {
			rw.Header().Set("X-Auth-Request-Preferred-Username", session.PreferredUsername)
		} else {
			rw.Header().Del("X-Auth-Request-Preferred-Username")
		}

		if p.PassAccessToken {
			if session.AccessToken != "" {
				rw.Header().Set("X-Auth-Request-Access-Token", session.AccessToken)
			} else {
				rw.Header().Del("X-Auth-Request-Access-Token")
			}
		}
	}

	if p.PassAccessToken {
		if session.AccessToken != "" {
			req.Header["X-Forwarded-Access-Token"] = []string{session.AccessToken}
		} else {
			req.Header.Del("X-Forwarded-Access-Token")
		}
	}

	if p.PassAuthorization {
		if session.IDToken != "" {
			req.Header["Authorization"] = []string{fmt.Sprintf("Bearer %s", session.IDToken)}
		} else {
			req.Header.Del("Authorization")
		}
	}
	if p.SetAuthorization {
		if session.IDToken != "" {
			rw.Header().Set("Authorization", fmt.Sprintf("Bearer %s", session.IDToken))
		} else {
			rw.Header().Del("Authorization")
		}
	}

	if session.Email == "" {
		rw.Header().Set("GAP-Auth", session.User)
	} else {
		rw.Header().Set("GAP-Auth", session.Email)
	}
}

// CheckBasicAuth checks the requests Authorization header for basic auth
// credentials and authenticates these against the proxies HtpasswdFile
func (p *OAuthProxy) CheckBasicAuth(req *http.Request) (*sessionsapi.SessionState, error) {
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
		return &sessionsapi.SessionState{User: pair[0]}, nil
	}
	logger.PrintAuthf(pair[0], req, logger.AuthFailure, "Invalid authentication via basic auth: not in Htpasswd File")
	return nil, nil
}

// isAjax checks if a request is an ajax request
func isAjax(req *http.Request) bool {
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

// ErrorJSON returns the error code with an application/json mime type
func (p *OAuthProxy) ErrorJSON(rw http.ResponseWriter, code int) {
	rw.Header().Set("Content-Type", applicationJSON)
	rw.WriteHeader(code)
}

// GetJwtSession loads a session based on a JWT token in the authorization header.
func (p *OAuthProxy) GetJwtSession(req *http.Request) (*sessionsapi.SessionState, error) {
	rawBearerToken, err := p.findBearerToken(req)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	var session *sessionsapi.SessionState
	for _, verifier := range p.jwtBearerVerifiers {
		bearerToken, err := verifier.Verify(ctx, rawBearerToken)

		if err != nil {
			logger.Printf("failed to verify bearer token: %v", err)
			continue
		}

		var claims struct {
			Subject           string `json:"sub"`
			Email             string `json:"email"`
			Verified          *bool  `json:"email_verified"`
			PreferredUsername string `json:"preferred_username"`
		}

		if err := bearerToken.Claims(&claims); err != nil {
			return nil, fmt.Errorf("failed to parse bearer token claims: %v", err)
		}

		if claims.Email == "" {
			claims.Email = claims.Subject
		}

		if claims.Verified != nil && !*claims.Verified {
			return nil, fmt.Errorf("email in id_token (%s) isn't verified", claims.Email)
		}

		session = &sessionsapi.SessionState{
			AccessToken:       rawBearerToken,
			IDToken:           rawBearerToken,
			RefreshToken:      "",
			ExpiresOn:         bearerToken.Expiry,
			Email:             claims.Email,
			User:              claims.Email,
			PreferredUsername: claims.PreferredUsername,
		}
		return session, nil
	}
	return nil, fmt.Errorf("unable to verify jwt token %s", req.Header.Get("Authorization"))
}

// findBearerToken finds a valid JWT token from the Authorization header of a given request.
func (p *OAuthProxy) findBearerToken(req *http.Request) (string, error) {
	auth := req.Header.Get("Authorization")
	s := strings.SplitN(auth, " ", 2)
	if len(s) != 2 {
		return "", fmt.Errorf("invalid authorization header %s", auth)
	}
	jwtRegex := regexp.MustCompile(`^eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+$`)
	var rawBearerToken string
	if s[0] == "Bearer" && jwtRegex.MatchString(s[1]) {
		rawBearerToken = s[1]
	} else if s[0] == "Basic" {
		// Check if we have a Bearer token masquerading in Basic
		b, err := b64.StdEncoding.DecodeString(s[1])
		if err != nil {
			return "", err
		}
		pair := strings.SplitN(string(b), ":", 2)
		if len(pair) != 2 {
			return "", fmt.Errorf("invalid format %s", b)
		}
		user, password := pair[0], pair[1]

		// check user, user+password, or just password for a token
		if jwtRegex.MatchString(user) {
			// Support blank passwords or magic `x-oauth-basic` passwords - nothing else
			if password == "" || password == "x-oauth-basic" {
				rawBearerToken = user
			}
		} else if jwtRegex.MatchString(password) {
			// support passwords and ignore user
			rawBearerToken = password
		}
	}
	if rawBearerToken == "" {
		return "", fmt.Errorf("no valid bearer token found in authorization header")
	}

	return rawBearerToken, nil
}
