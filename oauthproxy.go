package main

import (
	"context"
	"embed"
	"encoding/base64"
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
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/encryption"
	proxyhttp "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/http"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/version"

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
	staticPathPrefix  = "/static/"
)

var (
	// ErrNeedsLogin means the user should be redirected to the login page
	ErrNeedsLogin = errors.New("redirect to login page")

	// ErrAccessDenied means the user should receive a 401 Unauthorized response
	ErrAccessDenied = errors.New("access denied")

	//go:embed static/*
	staticFiles embed.FS
)

// allowedRoute manages method + path based allowlists
type allowedRoute struct {
	method    string
	negate    bool
	pathRegex *regexp.Regexp
}

type apiRoute struct {
	pathRegex *regexp.Regexp
}

// OAuthProxy is the main authentication proxy
type OAuthProxy struct {
	CookieOptions *options.Cookie
	Validator     func(string) bool

	SignInPath string

	allowedRoutes        []allowedRoute
	apiRoutes            []apiRoute
	redirectURL          *url.URL // the url to receive requests at
	relativeRedirectURL  bool
	whitelistDomains     []string
	provider             providers.Provider
	sessionStore         sessionsapi.SessionStore
	ProxyPrefix          string
	basicAuthValidator   basic.Validator
	basicAuthGroups      []string
	SkipProviderButton   bool
	skipAuthPreflight    bool
	skipJwtBearerTokens  bool
	forceJSONErrors      bool
	allowQuerySemicolons bool
	realClientIPParser   ipapi.RealClientIPParser
	trustedIPs           *ip.NetSet

	sessionChain      alice.Chain
	headersChain      alice.Chain
	preAuthChain      alice.Chain
	pageWriter        pagewriter.Writer
	server            proxyhttp.Server
	upstreamProxy     http.Handler
	serveMux          *mux.Router
	redirectValidator redirect.Validator
	appDirector       redirect.AppDirector

	encodeState bool
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
			return nil, fmt.Errorf("could not validate htpasswd: %v", err)
		}
	}

	provider, err := providers.NewProvider(opts.Providers[0])
	if err != nil {
		return nil, fmt.Errorf("error initialising provider: %v", err)
	}

	pageWriter, err := pagewriter.NewWriter(pagewriter.Opts{
		TemplatesPath:    opts.Templates.Path,
		CustomLogo:       opts.Templates.CustomLogo,
		ProxyPrefix:      opts.ProxyPrefix,
		Footer:           opts.Templates.Footer,
		Version:          version.VERSION,
		Debug:            opts.Templates.Debug,
		ProviderName:     buildProviderName(provider, opts.Providers[0].Name),
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

	logger.Printf("OAuthProxy configured for %s Client ID: %s", provider.Data().ProviderName, opts.Providers[0].ClientID)
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

	apiRoutes, err := buildAPIRoutes(opts)
	if err != nil {
		return nil, err
	}

	preAuthChain, err := buildPreAuthChain(opts, sessionStore)
	if err != nil {
		return nil, fmt.Errorf("could not build pre-auth chain: %v", err)
	}
	sessionChain := buildSessionChain(opts, provider, sessionStore, basicAuthValidator)
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

		ProxyPrefix:          opts.ProxyPrefix,
		provider:             provider,
		sessionStore:         sessionStore,
		redirectURL:          redirectURL,
		relativeRedirectURL:  opts.RelativeRedirectURL,
		apiRoutes:            apiRoutes,
		allowedRoutes:        allowedRoutes,
		whitelistDomains:     opts.WhitelistDomains,
		skipAuthPreflight:    opts.SkipAuthPreflight,
		skipJwtBearerTokens:  opts.SkipJwtBearerTokens,
		realClientIPParser:   opts.GetRealClientIPParser(),
		SkipProviderButton:   opts.SkipProviderButton,
		forceJSONErrors:      opts.ForceJSONErrors,
		allowQuerySemicolons: opts.AllowQuerySemicolons,
		trustedIPs:           trustedIPs,

		basicAuthValidator: basicAuthValidator,
		basicAuthGroups:    opts.HtpasswdUserGroups,
		sessionChain:       sessionChain,
		headersChain:       headersChain,
		preAuthChain:       preAuthChain,
		pageWriter:         pageWriter,
		upstreamProxy:      upstreamProxy,
		redirectValidator:  redirectValidator,
		appDirector:        appDirector,
		encodeState:        opts.EncodeState,
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

	// Option: AllowQuerySemicolons
	if opts.AllowQuerySemicolons {
		serverOpts.Handler = http.AllowQuerySemicolons(serverOpts.Handler)
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
	// likelihood of multiple requests trying to refresh sessions simultaneously.
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
	s.Path(oauthStartPath).HandlerFunc(p.OAuthStart)
	s.Path(oauthCallbackPath).HandlerFunc(p.OAuthCallback)

	// Static file paths
	s.PathPrefix(staticPathPrefix).Handler(http.StripPrefix(p.ProxyPrefix, http.FileServer(http.FS(staticFiles))))

	// The userinfo and logout endpoints needs to load sessions before handling the request
	s.Path(userInfoPath).Handler(p.sessionChain.ThenFunc(p.UserInfo))
	s.Path(signOutPath).Handler(p.sessionChain.ThenFunc(p.SignOut))
}

// buildPreAuthChain constructs a chain that should process every request before
// the OAuth2 Proxy authentication logic kicks in.
// For example forcing HTTPS or health checks.
func buildPreAuthChain(opts *options.Options, sessionStore sessionsapi.SessionStore) (alice.Chain, error) {
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
			middleware.NewReadynessCheck(opts.ReadyPath, sessionStore),
			middleware.NewRequestLogger(),
		)
	} else {
		chain = chain.Append(
			middleware.NewRequestLogger(),
			middleware.NewHealthCheck(healthCheckPaths, healthCheckUserAgents),
			middleware.NewReadynessCheck(opts.ReadyPath, sessionStore),
		)
	}

	chain = chain.Append(middleware.NewRequestMetricsWithDefaultRegistry())

	return chain, nil
}

func buildSessionChain(opts *options.Options, provider providers.Provider, sessionStore sessionsapi.SessionStore, validator basic.Validator) alice.Chain {
	chain := alice.New()

	if opts.SkipJwtBearerTokens {
		sessionLoaders := []middlewareapi.TokenToSessionFunc{
			provider.CreateSessionFromToken,
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
		RefreshSession:  provider.RefreshSession,
		ValidateSession: provider.ValidateSession,
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
			negate = strings.Contains(methodPath, "!=")
		)

		parts := regexp.MustCompile("!?=").Split(methodPath, 2)
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
			negate:    negate,
			pathRegex: compiledRegex,
		})
	}

	return routes, nil
}

// buildAPIRoutes builds an []apiRoute from ApiRoutes option
func buildAPIRoutes(opts *options.Options) ([]apiRoute, error) {
	routes := make([]apiRoute, 0, len(opts.APIRoutes))

	for _, path := range opts.APIRoutes {
		compiledRegex, err := regexp.Compile(path)
		if err != nil {
			return nil, err
		}
		logger.Printf("API route - Path: %s", path)
		routes = append(routes, apiRoute{
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

func isAllowedMethod(req *http.Request, route allowedRoute) bool {
	return route.method == "" || req.Method == route.method
}

func isAllowedPath(req *http.Request, route allowedRoute) bool {
	matches := route.pathRegex.MatchString(requestutil.GetRequestURI(req))

	if route.negate {
		return !matches
	}

	return matches
}

// IsAllowedRoute is used to check if the request method & path is allowed without auth
func (p *OAuthProxy) isAllowedRoute(req *http.Request) bool {
	for _, route := range p.allowedRoutes {
		if isAllowedMethod(req, route) && isAllowedPath(req, route) {
			return true
		}
	}
	return false
}

func (p *OAuthProxy) isAPIPath(req *http.Request) bool {
	for _, route := range p.apiRoutes {
		if route.pathRegex.MatchString(requestutil.GetRequestURI(req)) {
			return true
		}
	}
	return false
}

// isTrustedIP is used to check if a request comes from a trusted client IP address.
func (p *OAuthProxy) isTrustedIP(req *http.Request) bool {
	// RemoteAddr @ means unix socket
	// https://github.com/golang/go/blob/0fa53e41f122b1661d0678a6d36d71b7b5ad031d/src/syscall/syscall_linux.go#L506-L511
	if p.trustedIPs == nil && req.RemoteAddr != "@" {
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

// SignInPage writes the sign in template to the response
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

	p.pageWriter.WriteSignInPage(rw, req, redirectURL, code)
}

// ManualSignIn handles basic auth logins to the proxy
func (p *OAuthProxy) ManualSignIn(req *http.Request) (string, bool, int) {
	if req.Method != "POST" || p.basicAuthValidator == nil {
		return "", false, http.StatusOK
	}
	user := req.FormValue("username")
	passwd := req.FormValue("password")
	if user == "" {
		return "", false, http.StatusBadRequest
	}
	// check auth
	if p.basicAuthValidator.Validate(user, passwd) {
		logger.PrintAuthf(user, req, logger.AuthSuccess, "Authenticated via HtpasswdFile")
		return user, true, http.StatusOK
	}
	logger.PrintAuthf(user, req, logger.AuthFailure, "Invalid authentication via HtpasswdFile")
	return "", false, http.StatusUnauthorized
}

// SignIn serves a page prompting users to sign in
func (p *OAuthProxy) SignIn(rw http.ResponseWriter, req *http.Request) {
	redirect, err := p.appDirector.GetRedirect(req)
	if err != nil {
		logger.Errorf("Error obtaining redirect: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}

	user, ok, statusCode := p.ManualSignIn(req)
	if ok {
		session := &sessionsapi.SessionState{User: user, Groups: p.basicAuthGroups}
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
			// TODO - should we pass on /oauth2/sign_in query params to /oauth2/start?
			p.SignInPage(rw, req, statusCode)
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

	p.backendLogout(rw, req)

	http.Redirect(rw, req, redirect, http.StatusFound)
}

func (p *OAuthProxy) backendLogout(rw http.ResponseWriter, req *http.Request) {
	session, err := p.getAuthenticatedSession(rw, req)
	if err != nil {
		logger.Errorf("error getting authenticated session during backend logout: %v", err)
		return
	}

	if session == nil {
		return
	}

	providerData := p.provider.Data()
	if providerData.BackendLogoutURL == "" {
		return
	}

	backendLogoutURL := strings.ReplaceAll(providerData.BackendLogoutURL, "{id_token}", session.IDToken)
	// security exception because URL is dynamic ({id_token} replacement) but
	// base is not end-user provided but comes from configuration somewhat secure
	resp, err := http.Get(backendLogoutURL) // #nosec G107
	if err != nil {
		logger.Errorf("error while calling backend logout: %v", err)
		return
	}

	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		logger.Errorf("error while calling backend logout url, returned error code %v", resp.StatusCode)
	}
}

// OAuthStart starts the OAuth2 authentication flow
func (p *OAuthProxy) OAuthStart(rw http.ResponseWriter, req *http.Request) {
	// start the flow permitting login URL query parameters to be overridden from the request URL
	p.doOAuthStart(rw, req, req.URL.Query())
}

func (p *OAuthProxy) doOAuthStart(rw http.ResponseWriter, req *http.Request, overrides url.Values) {
	extraParams := p.provider.Data().LoginURLParams(overrides)
	prepareNoCache(rw)

	var (
		err                                              error
		codeChallenge, codeVerifier, codeChallengeMethod string
	)
	if p.provider.Data().CodeChallengeMethod != "" {
		codeChallengeMethod = p.provider.Data().CodeChallengeMethod
		codeVerifier, err = encryption.GenerateCodeVerifierString(96)
		if err != nil {
			logger.Errorf("Unable to build random ASCII string for code verifier: %v", err)
			p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
			return
		}

		codeChallenge, err = encryption.GenerateCodeChallenge(p.provider.Data().CodeChallengeMethod, codeVerifier)
		if err != nil {
			logger.Errorf("Error creating code challenge: %v", err)
			p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
			return
		}

		extraParams.Add("code_challenge", codeChallenge)
		extraParams.Add("code_challenge_method", codeChallengeMethod)
	}

	csrf, err := cookies.NewCSRF(p.CookieOptions, codeVerifier)
	if err != nil {
		logger.Errorf("Error creating CSRF nonce: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}

	appRedirect, err := p.appDirector.GetRedirect(req)
	if err != nil {
		logger.Errorf("Error obtaining application redirect: %v", err)
		p.ErrorPage(rw, req, http.StatusBadRequest, err.Error())
		return
	}

	callbackRedirect := p.getOAuthRedirectURI(req)
	loginURL := p.provider.GetLoginURL(
		callbackRedirect,
		encodeState(csrf.HashOAuthState(), appRedirect, p.encodeState),
		csrf.HashOIDCNonce(),
		extraParams,
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

	nonce, appRedirect, err := decodeState(req.Form.Get("state"), p.encodeState)
	if err != nil {
		logger.Errorf("Error while parsing OAuth2 state: %v", err)
		p.ErrorPage(rw, req, http.StatusInternalServerError, err.Error())
		return
	}

	// calculate the cookie name
	cookieName := cookies.GenerateCookieName(p.CookieOptions, nonce)
	// Try to find the CSRF cookie and decode it
	csrf, err := cookies.LoadCSRFCookie(req, cookieName, p.CookieOptions)
	if err != nil {
		// There are a lot of issues opened complaining about missing CSRF cookies.
		// Try to log the INs and OUTs of OAuthProxy, to be easier to analyse these issues.
		LoggingCSRFCookiesInOAuthCallback(req, cookieName)
		logger.Println(req, logger.AuthFailure, "Invalid authentication via OAuth2: unable to obtain CSRF cookie: %s (state=%s)", err, nonce)
		p.ErrorPage(rw, req, http.StatusForbidden, err.Error(), "Login Failed: Unable to find a valid CSRF token. Please try again.")
		return
	}

	session, err := p.redeemCode(req, csrf.GetCodeVerifier())
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

	csrf.ClearCookie(rw, req)

	if !csrf.CheckOAuthState(nonce) {
		logger.PrintAuthf(session.Email, req, logger.AuthFailure, "Invalid authentication via OAuth2: CSRF token mismatch, potential attack")
		p.ErrorPage(rw, req, http.StatusForbidden, "CSRF token mismatch, potential attack", "Login Failed: Unable to find a valid CSRF token. Please try again.")
		return
	}

	csrf.SetSessionNonce(session)
	if !p.provider.ValidateSession(req.Context(), session) {
		logger.PrintAuthf(session.Email, req, logger.AuthFailure, "Session validation failed: %s", session)
		p.ErrorPage(rw, req, http.StatusForbidden, "Session validation failed")
		return
	}

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

func (p *OAuthProxy) redeemCode(req *http.Request, codeVerifier string) (*sessionsapi.SessionState, error) {
	code := req.Form.Get("code")
	if code == "" {
		return nil, providers.ErrMissingCode
	}

	redirectURI := p.getOAuthRedirectURI(req)
	s, err := p.provider.Redeem(req.Context(), redirectURI, code, codeVerifier)
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
	p.headersChain.Then(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
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
		if p.forceJSONErrors || isAjax(req) || p.isAPIPath(req) {
			logger.Printf("No valid authentication in request. Access Denied.")
			// no point redirecting an AJAX request
			p.errorJSON(rw, http.StatusUnauthorized)
			return
		}

		logger.Printf("No valid authentication in request. Initiating login.")
		if p.SkipProviderButton {
			// start OAuth flow, but only with the default login URL params - do not
			// consider this request's query params as potential overrides, since
			// the user did not explicitly start the login flow
			p.doOAuthStart(rw, req, nil)
		} else {
			p.SignInPage(rw, req, http.StatusForbidden)
		}

	case ErrAccessDenied:
		if p.forceJSONErrors {
			p.errorJSON(rw, http.StatusForbidden)
		} else {
			p.ErrorPage(rw, req, http.StatusForbidden, "The session failed authorization checks")
		}

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
	if p.relativeRedirectURL || p.redirectURL.Host != "" {
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
		cause := "unauthorized"
		if invalidEmail {
			cause = "invalid email"
		}

		logger.PrintAuthf(session.Email, req, logger.AuthFailure, "Invalid authorization via session (%s): removing session %s", cause, session)
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
func authOnlyAuthorize(req *http.Request, s *sessionsapi.SessionState) bool {
	// Allow requests previously allowed to be bypassed
	if s == nil {
		return true
	}

	constraints := []func(*http.Request, *sessionsapi.SessionState) bool{
		checkAllowedGroups,
		checkAllowedEmailDomains,
		checkAllowedEmails,
	}

	for _, constraint := range constraints {
		if !constraint(req, s) {
			return false
		}
	}

	return true
}

// extractAllowedEntities aims to extract and split allowed entities linked by a key,
// from an HTTP request query. Output is a map[string]struct{} where keys are valuable,
// the goal is to avoid time complexity O(N^2) while finding matches during membership checks.
func extractAllowedEntities(req *http.Request, key string) map[string]struct{} {
	entities := map[string]struct{}{}

	query := req.URL.Query()
	for _, allowedEntities := range query[key] {
		for _, entity := range strings.Split(allowedEntities, ",") {
			if entity != "" {
				entities[entity] = struct{}{}
			}
		}
	}

	return entities
}

// checkAllowedEmailDomains allow email domain restrictions based on the `allowed_email_domains`
// querystring parameter
func checkAllowedEmailDomains(req *http.Request, s *sessionsapi.SessionState) bool {
	allowedEmailDomains := extractAllowedEntities(req, "allowed_email_domains")
	if len(allowedEmailDomains) == 0 {
		return true
	}

	splitEmail := strings.Split(s.Email, "@")
	if len(splitEmail) != 2 {
		return false
	}

	endpoint, _ := url.Parse("")
	endpoint.Host = splitEmail[1]

	allowedEmailDomainsList := []string{}
	for ed := range allowedEmailDomains {
		allowedEmailDomainsList = append(allowedEmailDomainsList, ed)
	}

	return util.IsEndpointAllowed(endpoint, allowedEmailDomainsList)
}

// checkAllowedGroups allow secondary group restrictions based on the `allowed_groups`
// querystring parameter
func checkAllowedGroups(req *http.Request, s *sessionsapi.SessionState) bool {
	allowedGroups := extractAllowedEntities(req, "allowed_groups")
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

// checkAllowedEmails allow email restrictions based on the `allowed_emails`
// querystring parameter
func checkAllowedEmails(req *http.Request, s *sessionsapi.SessionState) bool {
	allowedEmails := extractAllowedEntities(req, "allowed_emails")
	if len(allowedEmails) == 0 {
		return true
	}

	allowed := false

	for email := range allowedEmails {
		if email == s.Email {
			allowed = true
			break
		}
	}

	return allowed
}

// encodeState builds the OAuth state param out of our nonce and
// original application redirect
func encodeState(nonce string, redirect string, encode bool) string {
	rawString := fmt.Sprintf("%v:%v", nonce, redirect)
	if encode {
		return base64.RawURLEncoding.EncodeToString([]byte(rawString))
	}
	return rawString
}

// decodeState splits the reflected OAuth state response back into
// the nonce and original application redirect
func decodeState(state string, encode bool) (string, string, error) {
	toParse := state
	if encode {
		decoded, _ := base64.RawURLEncoding.DecodeString(state)
		toParse = string(decoded)
	}

	parsedState := strings.SplitN(toParse, ":", 2)
	if len(parsedState) != 2 {
		return "", "", errors.New("invalid length")
	}
	return parsedState[0], parsedState[1], nil
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
	// we need to send some JSON response because we set the Content-Type to
	// application/json
	rw.Write([]byte("{}"))
}

// LoggingCSRFCookiesInOAuthCallback Log all CSRF cookies found in HTTP request OAuth callback,
// which were successfully parsed
func LoggingCSRFCookiesInOAuthCallback(req *http.Request, cookieName string) {
	cookies := req.Cookies()
	if len(cookies) == 0 {
		logger.Println(req, logger.AuthFailure, "No cookies were found in OAuth callback.")
		return
	}

	for _, c := range cookies {
		if cookieName == c.Name {
			logger.Println(req, logger.AuthFailure, "CSRF cookie %s was found in OAuth callback.", c.Name)
			return
		}

		if strings.HasSuffix(c.Name, "_csrf") {
			logger.Println(req, logger.AuthFailure, "CSRF cookie %s was found in OAuth callback, but it is not the expected one (%s).", c.Name, cookieName)
			return
		}
	}

	logger.Println(req, logger.AuthFailure, "Cookies were found in OAuth callback, but none was a CSRF cookie.")
}
