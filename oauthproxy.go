package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	ipapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/ip"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/app/pagewriter"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/app/redirect"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/authentication/basic"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/cookies"
	proxyhttp "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/http"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/ip"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/middleware"
	requestutil "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests/util"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/upstream"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
)

const (
	schemeHTTP      = "http"
	schemeHTTPS     = "https"
	applicationJSON = "application/json"

	robotsPath        = "/robots.txt"
	signInPath        = "/sign_in"
	signOutPath       = "/sign_out"
	oauthStartPath    = "/start"
	oauthCallbackPath = "/callback"
	authOnlyPath      = "/auth"
	userInfoPath      = "/userinfo"
)

var (
	// ErrNeedsLogin means the user should be redirected to the login page
	ErrNeedsLogin = errors.New("redirect to login page")

	// ErrAccessDenied means the user should receive a 401 Unauthorized response
	ErrAccessDenied = errors.New("access denied")
)

// allowedRoute manages method + path based allowlists
type allowedRoute struct {
	method    string
	pathRegex *regexp.Regexp
}

// OAuthProxy is the main authentication proxy
type OAuthProxy struct {
	CookieOptions *options.Cookie
	Validator     func(string) bool

	SignInPath string

	allowedRoutes       []allowedRoute
	redirectURL         *url.URL // the url to receive requests at
	whitelistDomains    []string
	provider            providers.Provider
	sessionStore        sessionsapi.SessionStore
	ProxyPrefix         string
	basicAuthValidator  basic.Validator
	SkipProviderButton  bool
	skipAuthPreflight   bool
	skipJwtBearerTokens bool
	realClientIPParser  ipapi.RealClientIPParser
	trustedIPs          *ip.NetSet

	sessionChain      alice.Chain
	headersChain      alice.Chain
	preAuthChain      alice.Chain
	pageWriter        pagewriter.Writer
	server            proxyhttp.Server
	upstreamProxy     http.Handler
	serveMux          *mux.Router
	redirectValidator redirect.Validator
	appDirector       redirect.AppDirector
}

// NewOAuthProxy creates a new instance of OAuthProxy from the options provided
func NewOAuthProxy(opts *options.Options, validator func(string) bool) (*OAuthProxy, error) {
	sessionStore, err := sessions.NewSessionStore(&opts.Session, &opts.Cookie)
	if err != nil {
		return nil, fmt.Errorf("error initialising session store: %v", err)
	}

	var basicAuthValidator basic.Validator
	if opts.HtpasswdFile != "" {
		logger.Printf("using htpasswd file: %s", opts.HtpasswdFile)
		var err error
		basicAuthValidator, err = basic.NewHTPasswdValidator(opts.HtpasswdFile)
		if err != nil {
			return nil, fmt.Errorf("could not load htpasswdfile: %v", err)
		}
	}

	pageWriter, err := pagewriter.NewWriter(pagewriter.Opts{
		TemplatesPath:    opts.Templates.Path,
		CustomLogo:       opts.Templates.CustomLogo,
		ProxyPrefix:      opts.ProxyPrefix,
		Footer:           opts.Templates.Footer,
		Version:          VERSION,
		Debug:            opts.Templates.Debug,
		ProviderName:     buildProviderName(opts.GetProvider(), opts.Providers[0].Name),
		SignInMessage:    buildSignInMessage(opts),
		DisplayLoginForm: basicAuthValidator != nil && opts.Templates.DisplayLoginForm,
	})
	if err != nil {
		return nil, fmt.Errorf("error initialising page writer: %v", err)
	}

	upstreamProxy, err := upstream.NewProxy(opts.UpstreamServers, opts.GetSignatureData(), pageWriter)
	if err != nil {
		return nil, fmt.Errorf("error initialising upstream proxy: %v", err)
	}

	if opts.SkipJwtBearerTokens {
		logger.Printf("Skipping JWT tokens from configured OIDC issuer: %q", opts.Providers[0].OIDCConfig.IssuerURL)
		for _, issuer := range opts.ExtraJwtIssuers {
			logger.Printf("Skipping JWT tokens from extra JWT issuer: %q", issuer)
		}
	}
	redirectURL := opts.GetRedirectURL()
	if redirectURL.Path == "" {
		redirectURL.Path = fmt.Sprintf("%s/callback", opts.ProxyPrefix)
	}

	logger.Printf("OAuthProxy configured for %s Client ID: %s", opts.GetProvider().Data().ProviderName, opts.Providers[0].ClientID)
	refresh := "disabled"
	if opts.Cookie.Refresh != time.Duration(0) {
		refresh = fmt.Sprintf("after %s", opts.Cookie.Refresh)
	}

	logger.Printf("Cookie settings: name:%s secure(https):%v httponly:%v expiry:%s domains:%s path:%s samesite:%s refresh:%s", opts.Cookie.Name, opts.Cookie.Secure, opts.Cookie.HTTPOnly, opts.Cookie.Expire, strings.Join(opts.Cookie.Domains, ","), opts.Cookie.Path, opts.Cookie.SameSite, refresh)

	trustedIPs := ip.NewNetSet()
	for _, ipStr := range opts.TrustedIPs {
		if ipNet := ip.ParseIPNet(ipStr); ipNet != nil {
			trustedIPs.AddIPNet(*ipNet)
		} else {
			return nil, fmt.Errorf("could not parse IP network (%s)", ipStr)
		}
	}

	allowedRoutes, err := buildRoutesAllowlist(opts)
	if err != nil {
		return nil, err
	}

	preAuthChain, err := buildPreAuthChain(opts)
	if err != nil {
		return nil, fmt.Errorf("could not build pre-auth chain: %v", err)
	}
	sessionChain := buildSessionChain(opts, sessionStore, basicAuthValidator)
	headersChain, err := buildHeadersChain(opts)
	if err != nil {
		return nil, fmt.Errorf("could not build headers chain: %v", err)
	}

	redirectValidator := redirect.NewValidator(opts.WhitelistDomains)
	appDirector := redirect.NewAppDirector(redirect.AppDirectorOpts{
		ProxyPrefix: opts.ProxyPrefix,
		Validator:   redirectValidator,
	})

	p := &OAuthProxy{
		CookieOptions: &opts.Cookie,
		Validator:     validator,

		SignInPath: fmt.Sprintf("%s/sign_in", opts.ProxyPrefix),

		ProxyPrefix:         opts.ProxyPrefix,
		provider:            opts.GetProvider(),
		sessionStore:        sessionStore,
		redirectURL:         redirectURL,
		allowedRoutes:       allowedRoutes,
		whitelistDomains:    opts.WhitelistDomains,
		skipAuthPreflight:   opts.SkipAuthPreflight,
		skipJwtBearerTokens: opts.SkipJwtBearerTokens,
		realClientIPParser:  opts.GetRealClientIPParser(),
		SkipProviderButton:  opts.SkipProviderButton,
		trustedIPs:          trustedIPs,

		basicAuthValidator: basicAuthValidator,
		sessionChain:       sessionChain,
		headersChain:       headersChain,
		preAuthChain:       preAuthChain,
		pageWriter:         pageWriter,
		upstreamProxy:      upstreamProxy,
		redirectValidator:  redirectValidator,
		appDirector:        appDirector,
	}
	p.buildServeMux(opts.ProxyPrefix)

	if err := p.setupServer(opts); err != nil {
		return nil, fmt.Errorf("error setting up server: %v", err)
	}

	return p, nil
}

func (p *OAuthProxy) Start() error {
	if p.server == nil {
		// We have to call setupServer before Start is called.
		// If this doesn't happen it's a programming error.
		panic("server has not been initialised")
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Observe signals in background goroutine.
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, syscall.SIGTERM)
		<-sigint
		cancel() // cancel the context
	}()

	return p.server.Start(ctx)
}

func (p *OAuthProxy) setupServer(opts *options.Options) error {
	serverOpts := proxyhttp.Opts{
		Handler:           p,
		BindAddress:       opts.Server.BindAddress,
		SecureBindAddress: opts.Server.SecureBindAddress,
		TLS:               opts.Server.TLS,
	}

	appServer, err := proxyhttp.NewServer(serverOpts)
	if err != nil {
		return fmt.Errorf("could not build app server: %v", err)
	}

	metricsServer, err := proxyhttp.NewServer(proxyhttp.Opts{
		Handler:           middleware.DefaultMetricsHandler,
		BindAddress:       opts.MetricsServer.BindAddress,
		SecureBindAddress: opts.MetricsServer.SecureBindAddress,
		TLS:               opts.MetricsServer.TLS,
	})
	if err != nil {
		return fmt.Errorf("could not build metrics server: %v", err)
	}

	p.server = proxyhttp.NewServerGroup(appServer, metricsServer)
	return nil
}

func (p *OAuthProxy) buildServeMux(proxyPrefix string) {
	// Use the encoded path here so we can have the option to pass it on in the upstream mux.
	// Otherwise something like /%2F/ would be redirected to / here already.
	r := mux.NewRouter().UseEncodedPath()
	// Everything served by the router must go through the preAuthChain first.
	r.Use(p.preAuthChain.Then)

	// Register the robots path writer
	r.Path(robotsPath).HandlerFunc(p.pageWriter.WriteRobotsTxt)

	// The authonly path should be registered separately to prevent it from getting no-cache headers.
	// We do this to allow users to have a short cache (via nginx) of the response to reduce the
	// likelihood of multiple reuests trying to referesh sessions simultaneously.
	r.Path(proxyPrefix + authOnlyPath).Handler(p.sessionChain.ThenFunc(p.AuthOnly))

	// This will register all of the paths under the proxy prefix, except the auth only path so that no cache headers
	// are not applied.
	p.buildProxySubrouter(r.PathPrefix(proxyPrefix).Subrouter())

	// Register serveHTTP last so it catches anything that isn't already caught earlier.
	// Anything that got to this point needs to have a session loaded.
	r.PathPrefix("/").Handler(p.sessionChain.ThenFunc(p.Proxy))
	p.serveMux = r
}

func (p *OAuthProxy) buildProxySubrouter(s *mux.Router) {
	s.Use(prepareNoCacheMiddleware)

	s.Path(signInPath).HandlerFunc(p.SignIn)
	s.Path(signOutPath).HandlerFunc(p.SignOut)
	s.Path(oauthStartPath).HandlerFunc(p.OAuthStart)
	s.Path(oauthCallbackPath).HandlerFunc(p.OAuthCallback)

	// The userinfo endpoint needs to load sessions before handling the request
	s.Path(userInfoPath).Handler(p.sessionChain.ThenFunc(p.UserInfo))
}

// buildPreAuthChain constructs a chain that should process every request before
// the OAuth2 Proxy authentication logic kicks in.
// For example forcing HTTPS or health checks.
func buildPreAuthChain(opts *options.Options) (alice.Chain, error) {
	chain := alice.New(middleware.NewScope(opts.ReverseProxy, opts.Logging.RequestIDHeader))

	if opts.ForceHTTPS {
		_, httpsPort, err := net.SplitHostPort(opts.Server.SecureBindAddress)
		if err != nil {
			return alice.Chain{}, fmt.Errorf("invalid HTTPS address %q: %v", opts.Server.SecureBindAddress, err)
		}
		chain = chain.Append(middleware.NewRedirectToHTTPS(httpsPort))
	}

	healthCheckPaths := []string{opts.PingPath}
	healthCheckUserAgents := []string{opts.PingUserAgent}
	if opts.GCPHealthChecks {
		logger.Printf("WARNING: GCP HealthChecks are now deprecated: Reconfigure apps to use the ping path for liveness and readiness checks, set the ping user agent to \"GoogleHC/1.0\" to preserve existing behaviour")
		healthCheckPaths = append(healthCheckPaths, "/liveness_check", "/readiness_check")
		healthCheckUserAgents = append(healthCheckUserAgents, "GoogleHC/1.0")
	}

	// To silence logging of health checks, register the health check handler before
	// the logging handler
	if opts.Logging.SilencePing {
		chain = chain.Append(
			middleware.NewHealthCheck(healthCheckPaths, healthCheckUserAgents),
			middleware.NewRequestLogger(),
		)
	} else {
		chain = chain.Append(
			middleware.NewRequestLogger(),
			middleware.NewHealthCheck(healthCheckPaths, healthCheckUserAgents),
		)
	}

	chain = chain.Append(middleware.NewRequestMetricsWithDefaultRegistry())

	return chain, nil
}

func buildSessionChain(opts *options.Options, sessionStore sessionsapi.SessionStore, validator basic.Validator) alice.Chain {
	chain := alice.New()

	if opts.SkipJwtBearerTokens {
		sessionLoaders := []middlewareapi.TokenToSessionFunc{
			opts.GetProvider().CreateSessionFromToken,
		}

		for _, verifier := range opts.GetJWTBearerVerifiers() {
			sessionLoaders = append(sessionLoaders,
				middlewareapi.CreateTokenToSessionFunc(verifier.Verify))
		}

		chain = chain.Append(middleware.NewJwtSessionLoader(sessionLoaders))
	}

	if validator != nil {
		chain = chain.Append(middleware.NewBasicAuthSessionLoader(validator, opts.HtpasswdUserGroups, opts.LegacyPreferEmailToUser))
	}

	chain = chain.Append(middleware.NewStoredSessionLoader(&middleware.StoredSessionLoaderOptions{
		SessionStore:    sessionStore,
		RefreshPeriod:   opts.Cookie.Refresh,
		RefreshSession:  opts.GetProvider().RefreshSession,
		ValidateSession: opts.GetProvider().ValidateSession,
	}))

	return chain
}

func buildHeadersChain(opts *options.Options) (alice.Chain, error) {
	requestInjector, err := middleware.NewRequestHeaderInjector(opts.InjectRequestHeaders)
	if err != nil {
		return alice.Chain{}, fmt.Errorf("error constructing request header injector: %v", err)
	}

	responseInjector, err := middleware.NewResponseHeaderInjector(opts.InjectResponseHeaders)
	if err != nil {
		return alice.Chain{}, fmt.Errorf("error constructing request header injector: %v", err)
	}

	return alice.New(requestInjector, responseInjector), nil
}

func buildSignInMessage(opts *options.Options) string {
	var msg string
	if len(opts.Templates.Banner) >= 1 {
		if opts.Templates.Banner == "-" {
			msg = ""
		} else {
			msg = opts.Templates.Banner
		}
	} else if len(opts.EmailDomains) != 0 && opts.AuthenticatedEmailsFile == "" {
		if len(opts.EmailDomains) > 1 {
			msg = fmt.Sprintf("Authenticate using one of the following domains: %v", strings.Join(opts.EmailDomains, ", "))
		} else if opts.EmailDomains[0] != "*" {
			msg = fmt.Sprintf("Authenticate using %v", opts.EmailDomains[0])
		}
	}
	return msg
}

func buildProviderName(p providers.Provider, override string) string {
	if override != "" {
		return override
	}
	return p.Data().ProviderName
}

// buildRoutesAllowlist builds an []allowedRoute  list from either the legacy
// SkipAuthRegex option (paths only support) or newer SkipAuthRoutes option
// (method=path support)
func buildRoutesAllowlist(opts *options.Options) ([]allowedRoute, error) {
	routes := make([]allowedRoute, 0, len(opts.SkipAuthRegex)+len(opts.SkipAuthRoutes))

	for _, path := range opts.SkipAuthRegex {
		compiledRegex, err := regexp.Compile(path)
		if err != nil {
			return nil, err
		}
		logger.Printf("Skipping auth - Method: ALL | Path: %s", path)
		routes = append(routes, allowedRoute{
			method:    "",
			pathRegex: compiledRegex,
		})
	}

	for _, methodPath := range opts.SkipAuthRoutes {
		var (
			method string
			path   string
		)

		parts := strings.SplitN(methodPath, "=", 2)
		if len(parts) == 1 {
			method = ""
			path = parts[0]
		} else {
			method = strings.ToUpper(parts[0])
			path = parts[1]
		}

		compiledRegex, err := regexp.Compile(path)
		if err != nil {
			return nil, err
		}
		logger.Printf("Skipping auth - Method: %s | Path: %s", method, path)
		routes = append(routes, allowedRoute{
			method:    method,
			pathRegex: compiledRegex,
		})
	}

	return routes, nil
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

func (p *OAuthProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	p.serveMux.ServeHTTP(rw, req)
}

// ErrorPage writes an error response
func (p *OAuthProxy) ErrorPage(rw http.ResponseWriter, req *http.Request, code int, appError string, messages ...interface{}) {
	redirectURL, err := p.appDirector.GetRedirect(req)
	if err != nil {
		logger.Errorf("Error obtaining redirect: %v", err)
	}
	if redirectURL == p.SignInPath || redirectURL == "" {
		redirectURL = "/"
	}

	scope := middlewareapi.GetRequestScope(req)
	p.pageWriter.WriteErrorPage(rw, pagewriter.ErrorPageOpts{
		Status:      code,
		RedirectURL: redirectURL,
		RequestID:   scope.RequestID,
		AppError:    appError,
		Messages:    messages,
	})
}

// IsAllowedRequest is used to check if auth should be skipped for this request
func (p *OAuthProxy) IsAllowedRequest(req *http.Request) bool {
	isPreflightRequestAllowed := p.skipAuthPreflight && req.Method == "OPTIONS"
	return isPreflightRequestAllowed || p.isAllowedRoute(req) || p.isTrustedIP(req)
}

// IsAllowedRoute is used to check if the request method & path is allowed without auth
func (p *OAuthProxy) isAllowedRoute(req *http.Request) bool {
	for _, route := range p.allowedRoutes {
		if (route.method == "" || req.Method == route.method) && route.pathRegex.MatchString(req.URL.Path) {
			return true
		}
	}
	return false
}

// isTrustedIP is used to check if a request comes from a trusted client IP address.
func (p *OAuthProxy) isTrustedIP(req *http.Request) bool {
	if p.trustedIPs == nil {
		return false
	}

	remoteAddr, err := ip.GetClientIP(p.realClientIPParser, req)
	if err != nil {
		logger.Errorf("Error obtaining real IP for trusted IP list: %v", err)
		// Possibly spoofed X-Real-IP header
		return false
	}

	if remoteAddr == nil {
		return false
	}

	return p.trustedIPs.Has(remoteAddr)
}

// SignInPage writes the sing in template to the response
func (p *OAuthProxy) SignInPage(rw http.ResponseWriter, req *http.Request, code int) {
	prepareNoCache(rw)
	err := p.ClearSessionCookie(rw, req)
	if err != nil {
		logger.Printf("Error clearing session cookie: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}
	rw.WriteHeader(code)

	redirectURL, err := p.appDirector.GetRedirect(req)
	if err != nil {
		logger.Errorf("Error obtaining redirect: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}

	if redirectURL == p.SignInPath {
		redirectURL = "/"
	}

	p.pageWriter.WriteSignInPage(rw, req, redirectURL)
}

// ManualSignIn handles basic auth logins to the proxy
func (p *OAuthProxy) ManualSignIn(req *http.Request) (string, bool) {
	if req.Method != "POST" || p.basicAuthValidator == nil {
		return "", false
	}
	user := req.FormValue("username")
	passwd := req.FormValue("password")
	if user == "" {
		return "", false
	}
	// check auth
	if p.basicAuthValidator.Validate(user, passwd) {
		logger.PrintAuthf(user, req, logger.AuthSuccess, "Authenticated via HtpasswdFile")
		return user, true
	}
	logger.PrintAuthf(user, req, logger.AuthFailure, "Invalid authentication via HtpasswdFile")
	return "", false
}

// SignIn serves a page prompting users to sign in
func (p *OAuthProxy) SignIn(rw http.ResponseWriter, req *http.Request) {
	redirect, err := p.appDirector.GetRedirect(req)
	if err != nil {
		logger.Errorf("Error obtaining redirect: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}

	user, ok := p.ManualSignIn(req)
	if ok {
		session := &sessionsapi.SessionState{User: user}
		err = p.SaveSession(rw, req, session)
		if err != nil {
			logger.Printf("Error saving session: %v", err)
			p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
			return
		}
		http.Redirect(rw, req, redirect, http.StatusFound)
	} else {
		if p.SkipProviderButton {
			p.OAuthStart(rw, req)
		} else {
			p.SignInPage(rw, req, http.StatusOK)
		}
	}
}

// UserInfo endpoint outputs session email and preferred username in JSON format
func (p *OAuthProxy) UserInfo(rw http.ResponseWriter, req *http.Request) {
	session, err := p.getAuthenticatedSession(rw, req)
	if err != nil {
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	if session == nil {
		if _, err := rw.Write([]byte("{}")); err != nil {
			logger.Printf("Error encoding empty user info: %v", err)
			p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		}
		return
	}

	userInfo := struct {
		User              string   `json:"user"`
		Email             string   `json:"email"`
		Groups            []string `json:"groups,omitempty"`
		PreferredUsername string   `json:"preferredUsername,omitempty"`
	}{
		User:              session.User,
		Email:             session.Email,
		Groups:            session.Groups,
		PreferredUsername: session.PreferredUsername,
	}

	if err := json.NewEncoder(rw).Encode(userInfo); err != nil {
		logger.Printf("Error encoding user info: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
	}
}

// SignOut sends a response to clear the authentication cookie
func (p *OAuthProxy) SignOut(rw http.ResponseWriter, req *http.Request) {
	redirect, err := p.appDirector.GetRedirect(req)
	if err != nil {
		logger.Errorf("Error obtaining redirect: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}
	err = p.ClearSessionCookie(rw, req)
	if err != nil {
		logger.Errorf("Error clearing session cookie: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}
	http.Redirect(rw, req, redirect, http.StatusFound)
}

// OAuthStart starts the OAuth2 authentication flow
func (p *OAuthProxy) OAuthStart(rw http.ResponseWriter, req *http.Request) {
	prepareNoCache(rw)

	csrf, err := cookies.NewCSRF(p.CookieOptions)
	if err != nil {
		logger.Errorf("Error creating CSRF nonce: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}

	appRedirect, err := p.appDirector.GetRedirect(req)
	if err != nil {
		logger.Errorf("Error obtaining application redirect: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}

	callbackRedirect := p.getOAuthRedirectURI(req)
	loginURL := p.provider.GetLoginURL(
		callbackRedirect,
		encodeState(csrf.HashOAuthState(), appRedirect),
		csrf.HashOIDCNonce(),
	)

	if _, err := csrf.SetCookie(rw, req); err != nil {
		logger.Errorf("Error setting CSRF cookie: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}

	http.Redirect(rw, req, loginURL, http.StatusFound)
}

// OAuthCallback is the OAuth2 authentication flow callback that finishes the
// OAuth2 authentication flow
func (p *OAuthProxy) OAuthCallback(rw http.ResponseWriter, req *http.Request) {
	remoteAddr := ip.GetClientString(p.realClientIPParser, req, true)

	// finish the oauth cycle
	err := req.ParseForm()
	if err != nil {
		logger.Errorf("Error while parsing OAuth2 callback: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}
	errorString := req.Form.Get("error")
	if errorString != "" {
		logger.Errorf("Error while parsing OAuth2 callback: %s", errorString)
		message := fmt.Sprintf("Login Failed: The upstream identity provider returned an error: %s", errorString)
		// Set the debug message and override the non debug message to be the same for this case
		p.ErrorPage(rw, req, http.StatusForbidden, message, message)
		return
	}

	session, err := p.redeemCode(req)
	if err != nil {
		logger.Errorf("Error redeeming code during OAuth2 callback: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}

	err = p.enrichSessionState(req.Context(), session)
	if err != nil {
		logger.Errorf("Error creating session during OAuth2 callback: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}

	csrf, err := cookies.LoadCSRFCookie(req, p.CookieOptions)
	if err != nil {
		logger.PrintAuthf(session.Email, req, logger.AuthFailure, "Invalid authentication via OAuth2: unable to obtain CSRF cookie")
		p.ErrorPage(rw, req, http.StatusForbidden, err.Error(), "Login Failed: Unable to find a valid CSRF token. Please try again.")
		return
	}

	csrf.ClearCookie(rw, req)

	nonce, appRedirect, err := decodeState(req)
	if err != nil {
		logger.Errorf("Error while parsing OAuth2 state: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}

	if !csrf.CheckOAuthState(nonce) {
		logger.PrintAuthf(session.Email, req, logger.AuthFailure, "Invalid authentication via OAuth2: CSRF token mismatch, potential attack")
		p.ErrorPage(rw, req, http.StatusForbidden, "CSRF token mismatch, potential attack", "Login Failed: Unable to find a valid CSRF token. Please try again.")
		return
	}

	csrf.SetSessionNonce(session)
	p.provider.ValidateSession(req.Context(), session)

	if !p.redirectValidator.IsValidRedirect(appRedirect) {
		appRedirect = "/"
	}

	// set cookie, or deny
	authorized, err := p.provider.Authorize(req.Context(), session)
	if err != nil {
		logger.Errorf("Error with authorization: %v", err)
	}
	if p.Validator(session.Email) && authorized {
		logger.PrintAuthf(session.Email, req, logger.AuthSuccess, "Authenticated via OAuth2: %s", session)
		err := p.SaveSession(rw, req, session)
		if err != nil {
			logger.Errorf("Error saving session state for %s: %v", remoteAddr, err)
			p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
			return
		}
		http.Redirect(rw, req, appRedirect, http.StatusFound)
	} else {
		logger.PrintAuthf(session.Email, req, logger.AuthFailure, "Invalid authentication via OAuth2: unauthorized")
		p.ErrorPage(rw, req, http.StatusForbidden, "Invalid session: unauthorized")
	}
}

func (p *OAuthProxy) redeemCode(req *http.Request) (*sessionsapi.SessionState, error) {
	code := req.Form.Get("code")
	if code == "" {
		return nil, providers.ErrMissingCode
	}

	redirectURI := p.getOAuthRedirectURI(req)
	s, err := p.provider.Redeem(req.Context(), redirectURI, code)
	if err != nil {
		return nil, err
	}

	// Force setting these in case the Provider didn't
	if s.CreatedAt == nil {
		s.CreatedAtNow()
	}
	if s.ExpiresOn == nil {
		s.ExpiresIn(p.CookieOptions.Expire)
	}

	return s, nil
}

func (p *OAuthProxy) enrichSessionState(ctx context.Context, s *sessionsapi.SessionState) error {
	var err error
	if s.Email == "" {
		// TODO(@NickMeves): Remove once all provider are updated to implement EnrichSession
		// nolint:staticcheck
		s.Email, err = p.provider.GetEmailAddress(ctx, s)
		if err != nil && !errors.Is(err, providers.ErrNotImplemented) {
			return err
		}
	}

	return p.provider.EnrichSession(ctx, s)
}

// AuthOnly checks whether the user is currently logged in (both authentication
// and optional authorization).
func (p *OAuthProxy) AuthOnly(rw http.ResponseWriter, req *http.Request) {
	session, err := p.getAuthenticatedSession(rw, req)
	if err != nil {
		http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// Unauthorized cases need to return 403 to prevent infinite redirects with
	// subrequest architectures
	if !authOnlyAuthorize(req, session) {
		http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	// we are authenticated
	p.addHeadersForProxying(rw, session)
	p.headersChain.Then(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusAccepted)
	})).ServeHTTP(rw, req)
}

// Proxy proxies the user request if the user is authenticated else it prompts
// them to authenticate
func (p *OAuthProxy) Proxy(rw http.ResponseWriter, req *http.Request) {
	session, err := p.getAuthenticatedSession(rw, req)
	switch err {
	case nil:
		// we are authenticated
		p.addHeadersForProxying(rw, session)
		p.headersChain.Then(p.upstreamProxy).ServeHTTP(rw, req)
	case ErrNeedsLogin:
		// we need to send the user to a login screen
		if isAjax(req) {
			// no point redirecting an AJAX request
			p.errorJSON(rw, http.StatusUnauthorized)
			return
		}

		if p.SkipProviderButton {
			p.OAuthStart(rw, req)
		} else {
			p.SignInPage(rw, req, http.StatusForbidden)
		}

	case ErrAccessDenied:
		p.ErrorPage(rw, req, http.StatusForbidden, "The session failed authorization checks")

	default:
		// unknown error
		logger.Errorf("Unexpected internal error: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
	}
}

// See https://developers.google.com/web/fundamentals/performance/optimizing-content-efficiency/http-caching?hl=en
var noCacheHeaders = map[string]string{
	"Expires":         time.Unix(0, 0).Format(time.RFC1123),
	"Cache-Control":   "no-cache, no-store, must-revalidate, max-age=0",
	"X-Accel-Expires": "0", // https://www.nginx.com/resources/wiki/start/topics/examples/x-accel/
}

// prepareNoCache prepares headers for preventing browser caching.
func prepareNoCache(w http.ResponseWriter) {
	// Set NoCache headers
	for k, v := range noCacheHeaders {
		w.Header().Set(k, v)
	}
}

func prepareNoCacheMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		prepareNoCache(rw)
		next.ServeHTTP(rw, req)
	})
}

// getOAuthRedirectURI returns the redirectURL that the upstream OAuth Provider will
// redirect clients to once authenticated.
// This is usually the OAuthProxy callback URL.
func (p *OAuthProxy) getOAuthRedirectURI(req *http.Request) string {
	// if `p.redirectURL` already has a host, return it
	if p.redirectURL.Host != "" {
		return p.redirectURL.String()
	}

	// Otherwise figure out the scheme + host from the request
	rd := *p.redirectURL
	rd.Host = requestutil.GetRequestHost(req)
	rd.Scheme = requestutil.GetRequestProto(req)

	// If there's no scheme in the request, we should still include one
	if rd.Scheme == "" {
		rd.Scheme = schemeHTTP
	}

	// If CookieSecure is true, return `https` no matter what
	// Not all reverse proxies set X-Forwarded-Proto
	if p.CookieOptions.Secure {
		rd.Scheme = schemeHTTPS
	}
	return rd.String()
}

// getAuthenticatedSession checks whether a user is authenticated and returns a session object and nil error if so
// Returns:
// - `nil, ErrNeedsLogin` if user needs to login.
// - `nil, ErrAccessDenied` if the authenticated user is not authorized
// Set-Cookie headers may be set on the response as a side-effect of calling this method.
func (p *OAuthProxy) getAuthenticatedSession(rw http.ResponseWriter, req *http.Request) (*sessionsapi.SessionState, error) {
	session := middlewareapi.GetRequestScope(req).Session

	// Check this after loading the session so that if a valid session exists, we can add headers from it
	if p.IsAllowedRequest(req) {
		return session, nil
	}

	if session == nil {
		return nil, ErrNeedsLogin
	}

	invalidEmail := session.Email != "" && !p.Validator(session.Email)
	authorized, err := p.provider.Authorize(req.Context(), session)
	if err != nil {
		logger.Errorf("Error with authorization: %v", err)
	}

	if invalidEmail || !authorized {
		logger.PrintAuthf(session.Email, req, logger.AuthFailure, "Invalid authorization via session: removing session %s", session)
		// Invalid session, clear it
		err := p.ClearSessionCookie(rw, req)
		if err != nil {
			logger.Errorf("Error clearing session cookie: %v", err)
		}
		return nil, ErrAccessDenied
	}

	return session, nil
}

// authOnlyAuthorize handles special authorization logic that is only done
// on the AuthOnly endpoint for use with Nginx subrequest architectures.
//
// TODO (@NickMeves): This method is a placeholder to be extended but currently
// fails the linter. Remove the nolint when functionality expands.
//
//nolint:gosimple
func authOnlyAuthorize(req *http.Request, s *sessionsapi.SessionState) bool {
	// Allow secondary group restrictions based on the `allowed_groups`
	// querystring parameter
	if !checkAllowedGroups(req, s) {
		return false
	}

	return true
}

func checkAllowedGroups(req *http.Request, s *sessionsapi.SessionState) bool {
	allowedGroups := extractAllowedGroups(req)
	if len(allowedGroups) == 0 {
		return true
	}

	for _, group := range s.Groups {
		if _, ok := allowedGroups[group]; ok {
			return true
		}
	}

	return false
}

func extractAllowedGroups(req *http.Request) map[string]struct{} {
	groups := map[string]struct{}{}

	query := req.URL.Query()
	for _, allowedGroups := range query["allowed_groups"] {
		for _, group := range strings.Split(allowedGroups, ",") {
			if group != "" {
				groups[group] = struct{}{}
			}
		}
	}

	return groups
}

// encodedState builds the OAuth state param out of our nonce and
// original application redirect
func encodeState(nonce string, redirect string) string {
	return fmt.Sprintf("%v:%v", nonce, redirect)
}

// decodeState splits the reflected OAuth state response back into
// the nonce and original application redirect
func decodeState(req *http.Request) (string, string, error) {
	state := strings.SplitN(req.Form.Get("state"), ":", 2)
	if len(state) != 2 {
		return "", "", errors.New("invalid length")
	}
	return state[0], state[1], nil
}

// addHeadersForProxying adds the appropriate headers the request / response for proxying
func (p *OAuthProxy) addHeadersForProxying(rw http.ResponseWriter, session *sessionsapi.SessionState) {
	if session == nil {
		return
	}
	if session.Email == "" {
		rw.Header().Set("GAP-Auth", session.User)
	} else {
		rw.Header().Set("GAP-Auth", session.Email)
	}
}

// isAjax checks if a request is an ajax request
func isAjax(req *http.Request) bool {
	acceptValues := req.Header.Values("Accept")
	const ajaxReq = applicationJSON
	// Iterate over multiple Accept headers, i.e.
	// Accept: application/json
	// Accept: text/plain
	for _, mimeTypes := range acceptValues {
		// Iterate over multiple mimetypes in a single header, i.e.
		// Accept: application/json, text/plain, */*
		for _, mimeType := range strings.Split(mimeTypes, ",") {
			mimeType = strings.TrimSpace(mimeType)
			if mimeType == ajaxReq {
				return true
			}
		}
	}
	return false
}

// errorJSON returns the error code with an application/json mime type
func (p *OAuthProxy) errorJSON(rw http.ResponseWriter, code int) {
	rw.Header().Set("Content-Type", applicationJSON)
	rw.WriteHeader(code)
}
