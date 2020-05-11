package options

import (
	"crypto"
	"net/url"
	"regexp"
	"time"

	oidc "github.com/coreos/go-oidc"
	ipapi "github.com/oauth2-proxy/oauth2-proxy/pkg/apis/ip"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/providers"
	"github.com/spf13/pflag"
)

// SignatureData holds hmacauth signature hash and key
type SignatureData struct {
	Hash crypto.Hash
	Key  string
}

// Options holds Configuration Options that can be set by Command Line Flag,
// or Config File
type Options struct {
	ProxyPrefix        string `flag:"proxy-prefix" cfg:"proxy_prefix"`
	PingPath           string `flag:"ping-path" cfg:"ping_path"`
	ProxyWebSockets    bool   `flag:"proxy-websockets" cfg:"proxy_websockets"`
	HTTPAddress        string `flag:"http-address" cfg:"http_address"`
	HTTPSAddress       string `flag:"https-address" cfg:"https_address"`
	ReverseProxy       bool   `flag:"reverse-proxy" cfg:"reverse_proxy"`
	RealClientIPHeader string `flag:"real-client-ip-header" cfg:"real_client_ip_header"`
	ForceHTTPS         bool   `flag:"force-https" cfg:"force_https"`
	RawRedirectURL     string `flag:"redirect-url" cfg:"redirect_url"`
	ClientID           string `flag:"client-id" cfg:"client_id"`
	ClientSecret       string `flag:"client-secret" cfg:"client_secret"`
	ClientSecretFile   string `flag:"client-secret-file" cfg:"client_secret_file"`
	TLSCertFile        string `flag:"tls-cert-file" cfg:"tls_cert_file"`
	TLSKeyFile         string `flag:"tls-key-file" cfg:"tls_key_file"`

	AuthenticatedEmailsFile  string   `flag:"authenticated-emails-file" cfg:"authenticated_emails_file"`
	KeycloakGroup            string   `flag:"keycloak-group" cfg:"keycloak_group"`
	AzureTenant              string   `flag:"azure-tenant" cfg:"azure_tenant"`
	BitbucketTeam            string   `flag:"bitbucket-team" cfg:"bitbucket_team"`
	BitbucketRepository      string   `flag:"bitbucket-repository" cfg:"bitbucket_repository"`
	EmailDomains             []string `flag:"email-domain" cfg:"email_domains"`
	WhitelistDomains         []string `flag:"whitelist-domain" cfg:"whitelist_domains"`
	GitHubOrg                string   `flag:"github-org" cfg:"github_org"`
	GitHubTeam               string   `flag:"github-team" cfg:"github_team"`
	GitHubRepo               string   `flag:"github-repo" cfg:"github_repo"`
	GitHubToken              string   `flag:"github-token" cfg:"github_token"`
	GitLabGroup              string   `flag:"gitlab-group" cfg:"gitlab_group"`
	GoogleGroups             []string `flag:"google-group" cfg:"google_group"`
	GoogleAdminEmail         string   `flag:"google-admin-email" cfg:"google_admin_email"`
	GoogleServiceAccountJSON string   `flag:"google-service-account-json" cfg:"google_service_account_json"`
	HtpasswdFile             string   `flag:"htpasswd-file" cfg:"htpasswd_file"`
	DisplayHtpasswdForm      bool     `flag:"display-htpasswd-form" cfg:"display_htpasswd_form"`
	CustomTemplatesDir       string   `flag:"custom-templates-dir" cfg:"custom_templates_dir"`
	Banner                   string   `flag:"banner" cfg:"banner"`
	Footer                   string   `flag:"footer" cfg:"footer"`

	Cookie  CookieOptions  `cfg:",squash"`
	Session SessionOptions `cfg:",squash"`
	Logging Logging        `cfg:",squash"`

	Upstreams                     []string      `flag:"upstream" cfg:"upstreams"`
	SkipAuthRegex                 []string      `flag:"skip-auth-regex" cfg:"skip_auth_regex"`
	SkipJwtBearerTokens           bool          `flag:"skip-jwt-bearer-tokens" cfg:"skip_jwt_bearer_tokens"`
	ExtraJwtIssuers               []string      `flag:"extra-jwt-issuers" cfg:"extra_jwt_issuers"`
	PassBasicAuth                 bool          `flag:"pass-basic-auth" cfg:"pass_basic_auth"`
	SetBasicAuth                  bool          `flag:"set-basic-auth" cfg:"set_basic_auth"`
	PreferEmailToUser             bool          `flag:"prefer-email-to-user" cfg:"prefer_email_to_user"`
	BasicAuthPassword             string        `flag:"basic-auth-password" cfg:"basic_auth_password"`
	PassAccessToken               bool          `flag:"pass-access-token" cfg:"pass_access_token"`
	PassHostHeader                bool          `flag:"pass-host-header" cfg:"pass_host_header"`
	SkipProviderButton            bool          `flag:"skip-provider-button" cfg:"skip_provider_button"`
	PassUserHeaders               bool          `flag:"pass-user-headers" cfg:"pass_user_headers"`
	SSLInsecureSkipVerify         bool          `flag:"ssl-insecure-skip-verify" cfg:"ssl_insecure_skip_verify"`
	SSLUpstreamInsecureSkipVerify bool          `flag:"ssl-upstream-insecure-skip-verify" cfg:"ssl_upstream_insecure_skip_verify"`
	SetXAuthRequest               bool          `flag:"set-xauthrequest" cfg:"set_xauthrequest"`
	SetAuthorization              bool          `flag:"set-authorization-header" cfg:"set_authorization_header"`
	PassAuthorization             bool          `flag:"pass-authorization-header" cfg:"pass_authorization_header"`
	SkipAuthPreflight             bool          `flag:"skip-auth-preflight" cfg:"skip_auth_preflight"`
	FlushInterval                 time.Duration `flag:"flush-interval" cfg:"flush_interval"`

	// These options allow for other providers besides Google, with
	// potential overrides.
	ProviderType                       string `flag:"provider" cfg:"provider"`
	ProviderName                       string `flag:"provider-display-name" cfg:"provider_display_name"`
	OIDCIssuerURL                      string `flag:"oidc-issuer-url" cfg:"oidc_issuer_url"`
	InsecureOIDCAllowUnverifiedEmail   bool   `flag:"insecure-oidc-allow-unverified-email" cfg:"insecure_oidc_allow_unverified_email"`
	InsecureOIDCSkipIssuerVerification bool   `flag:"insecure-oidc-skip-issuer-verification" cfg:"insecure_oidc_skip_issuer_verification"`
	SkipOIDCDiscovery                  bool   `flag:"skip-oidc-discovery" cfg:"skip_oidc_discovery"`
	OIDCJwksURL                        string `flag:"oidc-jwks-url" cfg:"oidc_jwks_url"`
	LoginURL                           string `flag:"login-url" cfg:"login_url"`
	RedeemURL                          string `flag:"redeem-url" cfg:"redeem_url"`
	ProfileURL                         string `flag:"profile-url" cfg:"profile_url"`
	ProtectedResource                  string `flag:"resource" cfg:"resource"`
	ValidateURL                        string `flag:"validate-url" cfg:"validate_url"`
	Scope                              string `flag:"scope" cfg:"scope"`
	Prompt                             string `flag:"prompt" cfg:"prompt"`
	ApprovalPrompt                     string `flag:"approval-prompt" cfg:"approval_prompt"` // Deprecated by OIDC 1.0
	UserIDClaim                        string `flag:"user-id-claim" cfg:"user_id_claim"`

	SignatureKey    string `flag:"signature-key" cfg:"signature_key"`
	AcrValues       string `flag:"acr-values" cfg:"acr_values"`
	JWTKey          string `flag:"jwt-key" cfg:"jwt_key"`
	JWTKeyFile      string `flag:"jwt-key-file" cfg:"jwt_key_file"`
	PubJWKURL       string `flag:"pubjwk-url" cfg:"pubjwk_url"`
	GCPHealthChecks bool   `flag:"gcp-healthchecks" cfg:"gcp_healthchecks"`

	// internal values that are set after config validation
	redirectURL        *url.URL
	proxyURLs          []*url.URL
	compiledRegex      []*regexp.Regexp
	provider           providers.Provider
	sessionStore       sessionsapi.SessionStore
	signatureData      *SignatureData
	oidcVerifier       *oidc.IDTokenVerifier
	jwtBearerVerifiers []*oidc.IDTokenVerifier
	realClientIPParser ipapi.RealClientIPParser
}

// Options for Getting internal values
func (o *Options) GetRedirectURL() *url.URL                        { return o.redirectURL }
func (o *Options) GetProxyURLs() []*url.URL                        { return o.proxyURLs }
func (o *Options) GetCompiledRegex() []*regexp.Regexp              { return o.compiledRegex }
func (o *Options) GetProvider() providers.Provider                 { return o.provider }
func (o *Options) GetSessionStore() sessionsapi.SessionStore       { return o.sessionStore }
func (o *Options) GetSignatureData() *SignatureData                { return o.signatureData }
func (o *Options) GetOIDCVerifier() *oidc.IDTokenVerifier          { return o.oidcVerifier }
func (o *Options) GetJWTBearerVerifiers() []*oidc.IDTokenVerifier  { return o.jwtBearerVerifiers }
func (o *Options) GetRealClientIPParser() ipapi.RealClientIPParser { return o.realClientIPParser }

// Options for Setting internal values
func (o *Options) SetRedirectURL(s *url.URL)                        { o.redirectURL = s }
func (o *Options) SetProxyURLs(s []*url.URL)                        { o.proxyURLs = s }
func (o *Options) SetCompiledRegex(s []*regexp.Regexp)              { o.compiledRegex = s }
func (o *Options) SetProvider(s providers.Provider)                 { o.provider = s }
func (o *Options) SetSessionStore(s sessionsapi.SessionStore)       { o.sessionStore = s }
func (o *Options) SetSignatureData(s *SignatureData)                { o.signatureData = s }
func (o *Options) SetOIDCVerifier(s *oidc.IDTokenVerifier)          { o.oidcVerifier = s }
func (o *Options) SetJWTBearerVerifiers(s []*oidc.IDTokenVerifier)  { o.jwtBearerVerifiers = s }
func (o *Options) SetRealClientIPParser(s ipapi.RealClientIPParser) { o.realClientIPParser = s }

// NewOptions constructs a new Options with defaulted values
func NewOptions() *Options {
	return &Options{
		ProxyPrefix:         "/oauth2",
		ProviderType:        "google",
		PingPath:            "/ping",
		ProxyWebSockets:     true,
		HTTPAddress:         "127.0.0.1:4180",
		HTTPSAddress:        ":443",
		RealClientIPHeader:  "X-Real-IP",
		ForceHTTPS:          false,
		DisplayHtpasswdForm: true,
		Cookie: CookieOptions{
			Name:     "_oauth2_proxy",
			Secure:   true,
			HTTPOnly: true,
			Expire:   time.Duration(168) * time.Hour,
			Refresh:  time.Duration(0),
			Path:     "/",
		},
		Session: SessionOptions{
			Type: "cookie",
		},
		AzureTenant:                      "common",
		SetXAuthRequest:                  false,
		SkipAuthPreflight:                false,
		FlushInterval:                    time.Duration(1) * time.Second,
		PassBasicAuth:                    true,
		SetBasicAuth:                     false,
		PassUserHeaders:                  true,
		PassAccessToken:                  false,
		PassHostHeader:                   true,
		SetAuthorization:                 false,
		PassAuthorization:                false,
		PreferEmailToUser:                false,
		Prompt:                           "", // Change to "login" when ApprovalPrompt officially deprecated
		ApprovalPrompt:                   "force",
		UserIDClaim:                      "email",
		InsecureOIDCAllowUnverifiedEmail: false,
		SkipOIDCDiscovery:                false,
		Logging: Logging{
			ExcludePaths:    "",
			LocalTime:       true,
			SilencePing:     false,
			AuthEnabled:     true,
			AuthFormat:      logger.DefaultAuthLoggingFormat,
			RequestEnabled:  true,
			RequestFormat:   logger.DefaultRequestLoggingFormat,
			StandardEnabled: true,
			StandardFormat:  logger.DefaultStandardLoggingFormat,
			File: LogFileOptions{
				Filename:   "",
				MaxSize:    100,
				MaxAge:     7,
				MaxBackups: 0,
				Compress:   false,
			},
		},
	}
}

// NewFlagSet creates a new FlagSet with all of the flags required by Options
func NewFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("oauth2-proxy", pflag.ExitOnError)

	flagSet.String("http-address", "127.0.0.1:4180", "[http://]<addr>:<port> or unix://<path> to listen on for HTTP clients")
	flagSet.String("https-address", ":443", "<addr>:<port> to listen on for HTTPS clients")
	flagSet.Bool("reverse-proxy", false, "are we running behind a reverse proxy, controls whether headers like X-Real-Ip are accepted")
	flagSet.String("real-client-ip-header", "X-Real-IP", "Header used to determine the real IP of the client (one of: X-Forwarded-For, X-Real-IP, or X-ProxyUser-IP)")
	flagSet.Bool("force-https", false, "force HTTPS redirect for HTTP requests")
	flagSet.String("tls-cert-file", "", "path to certificate file")
	flagSet.String("tls-key-file", "", "path to private key file")
	flagSet.String("redirect-url", "", "the OAuth Redirect URL. ie: \"https://internalapp.yourcompany.com/oauth2/callback\"")
	flagSet.Bool("set-xauthrequest", false, "set X-Auth-Request-User and X-Auth-Request-Email response headers (useful in Nginx auth_request mode)")
	flagSet.StringSlice("upstream", []string{}, "the http url(s) of the upstream endpoint, file:// paths for static files or static://<status_code> for static response. Routing is based on the path")
	flagSet.Bool("pass-basic-auth", true, "pass HTTP Basic Auth, X-Forwarded-User and X-Forwarded-Email information to upstream")
	flagSet.Bool("set-basic-auth", false, "set HTTP Basic Auth information in response (useful in Nginx auth_request mode)")
	flagSet.Bool("prefer-email-to-user", false, "Prefer to use the Email address as the Username when passing information to upstream. Will only use Username if Email is unavailable, eg. htaccess authentication. Used in conjunction with -pass-basic-auth and -pass-user-headers")
	flagSet.Bool("pass-user-headers", true, "pass X-Forwarded-User and X-Forwarded-Email information to upstream")
	flagSet.String("basic-auth-password", "", "the password to set when passing the HTTP Basic Auth header")
	flagSet.Bool("pass-access-token", false, "pass OAuth access_token to upstream via X-Forwarded-Access-Token header")
	flagSet.Bool("pass-host-header", true, "pass the request Host Header to upstream")
	flagSet.Bool("pass-authorization-header", false, "pass the Authorization Header to upstream")
	flagSet.Bool("set-authorization-header", false, "set Authorization response headers (useful in Nginx auth_request mode)")
	flagSet.StringSlice("skip-auth-regex", []string{}, "bypass authentication for requests path's that match (may be given multiple times)")
	flagSet.Bool("skip-provider-button", false, "will skip sign-in-page to directly reach the next step: oauth/start")
	flagSet.Bool("skip-auth-preflight", false, "will skip authentication for OPTIONS requests")
	flagSet.Bool("ssl-insecure-skip-verify", false, "skip validation of certificates presented when using HTTPS providers")
	flagSet.Bool("ssl-upstream-insecure-skip-verify", false, "skip validation of certificates presented when using HTTPS upstreams")
	flagSet.Duration("flush-interval", time.Duration(1)*time.Second, "period between response flushing when streaming responses")
	flagSet.Bool("skip-jwt-bearer-tokens", false, "will skip requests that have verified JWT bearer tokens (default false)")
	flagSet.StringSlice("extra-jwt-issuers", []string{}, "if skip-jwt-bearer-tokens is set, a list of extra JWT issuer=audience pairs (where the issuer URL has a .well-known/openid-configuration or a .well-known/jwks.json)")

	flagSet.StringSlice("email-domain", []string{}, "authenticate emails with the specified domain (may be given multiple times). Use * to authenticate any email")
	flagSet.StringSlice("whitelist-domain", []string{}, "allowed domains for redirection after authentication. Prefix domain with a . to allow subdomains (eg .example.com)")
	flagSet.String("keycloak-group", "", "restrict login to members of this group.")
	flagSet.String("azure-tenant", "common", "go to a tenant-specific or common (tenant-independent) endpoint.")
	flagSet.String("bitbucket-team", "", "restrict logins to members of this team")
	flagSet.String("bitbucket-repository", "", "restrict logins to user with access to this repository")
	flagSet.String("github-org", "", "restrict logins to members of this organisation")
	flagSet.String("github-team", "", "restrict logins to members of this team")
	flagSet.String("github-repo", "", "restrict logins to collaborators of this repository")
	flagSet.String("github-token", "", "the token to use when verifying repository collaborators (must have push access to the repository)")
	flagSet.String("gitlab-group", "", "restrict logins to members of this group")
	flagSet.StringSlice("google-group", []string{}, "restrict logins to members of this google group (may be given multiple times).")
	flagSet.String("google-admin-email", "", "the google admin to impersonate for api calls")
	flagSet.String("google-service-account-json", "", "the path to the service account json credentials")
	flagSet.String("client-id", "", "the OAuth Client ID: ie: \"123456.apps.googleusercontent.com\"")
	flagSet.String("client-secret", "", "the OAuth Client Secret")
	flagSet.String("client-secret-file", "", "the file with OAuth Client Secret")
	flagSet.String("authenticated-emails-file", "", "authenticate against emails via file (one per line)")
	flagSet.String("htpasswd-file", "", "additionally authenticate against a htpasswd file. Entries must be created with \"htpasswd -s\" for SHA encryption or \"htpasswd -B\" for bcrypt encryption")
	flagSet.Bool("display-htpasswd-form", true, "display username / password login form if an htpasswd file is provided")
	flagSet.String("custom-templates-dir", "", "path to custom html templates")
	flagSet.String("banner", "", "custom banner string. Use \"-\" to disable default banner.")
	flagSet.String("footer", "", "custom footer string. Use \"-\" to disable default footer.")
	flagSet.String("proxy-prefix", "/oauth2", "the url root path that this proxy should be nested under (e.g. /<oauth2>/sign_in)")
	flagSet.String("ping-path", "/ping", "the ping endpoint that can be used for basic health checks")
	flagSet.Bool("proxy-websockets", true, "enables WebSocket proxying")

	flagSet.String("cookie-name", "_oauth2_proxy", "the name of the cookie that the oauth_proxy creates")
	flagSet.String("cookie-secret", "", "the seed string for secure cookies (optionally base64 encoded)")
	flagSet.StringSlice("cookie-domain", []string{}, "Optional cookie domains to force cookies to (ie: `.yourcompany.com`). The longest domain matching the request's host will be used (or the shortest cookie domain if there is no match).")
	flagSet.String("cookie-path", "/", "an optional cookie path to force cookies to (ie: /poc/)*")
	flagSet.Duration("cookie-expire", time.Duration(168)*time.Hour, "expire timeframe for cookie")
	flagSet.Duration("cookie-refresh", time.Duration(0), "refresh the cookie after this duration; 0 to disable")
	flagSet.Bool("cookie-secure", true, "set secure (HTTPS) cookie flag")
	flagSet.Bool("cookie-httponly", true, "set HttpOnly cookie flag")
	flagSet.String("cookie-samesite", "", "set SameSite cookie attribute (ie: \"lax\", \"strict\", \"none\", or \"\"). ")

	flagSet.String("session-store-type", "cookie", "the session storage provider to use")
	flagSet.String("redis-connection-url", "", "URL of redis server for redis session storage (eg: redis://HOST[:PORT])")
	flagSet.Bool("redis-use-sentinel", false, "Connect to redis via sentinels. Must set --redis-sentinel-master-name and --redis-sentinel-connection-urls to use this feature")
	flagSet.String("redis-sentinel-master-name", "", "Redis sentinel master name. Used in conjunction with --redis-use-sentinel")
	flagSet.String("redis-ca-path", "", "Redis custom CA path")
	flagSet.Bool("redis-insecure-skip-tls-verify", false, "Use insecure TLS connection to redis")
	flagSet.StringSlice("redis-sentinel-connection-urls", []string{}, "List of Redis sentinel connection URLs (eg redis://HOST[:PORT]). Used in conjunction with --redis-use-sentinel")
	flagSet.Bool("redis-use-cluster", false, "Connect to redis cluster. Must set --redis-cluster-connection-urls to use this feature")
	flagSet.StringSlice("redis-cluster-connection-urls", []string{}, "List of Redis cluster connection URLs (eg redis://HOST[:PORT]). Used in conjunction with --redis-use-cluster")

	flagSet.String("logging-filename", "", "File to log requests to, empty for stdout")
	flagSet.Int("logging-max-size", 100, "Maximum size in megabytes of the log file before rotation")
	flagSet.Int("logging-max-age", 7, "Maximum number of days to retain old log files")
	flagSet.Int("logging-max-backups", 0, "Maximum number of old log files to retain; 0 to disable")
	flagSet.Bool("logging-local-time", true, "If the time in log files and backup filenames are local or UTC time")
	flagSet.Bool("logging-compress", false, "Should rotated log files be compressed using gzip")

	flagSet.Bool("standard-logging", true, "Log standard runtime information")
	flagSet.String("standard-logging-format", logger.DefaultStandardLoggingFormat, "Template for standard log lines")

	flagSet.Bool("request-logging", true, "Log HTTP requests")
	flagSet.String("request-logging-format", logger.DefaultRequestLoggingFormat, "Template for HTTP request log lines")
	flagSet.String("exclude-logging-paths", "", "Exclude logging requests to paths (eg: '/path1,/path2,/path3')")
	flagSet.Bool("silence-ping-logging", false, "Disable logging of requests to ping endpoint")

	flagSet.Bool("auth-logging", true, "Log authentication attempts")
	flagSet.String("auth-logging-format", logger.DefaultAuthLoggingFormat, "Template for authentication log lines")

	flagSet.String("provider", "google", "OAuth provider")
	flagSet.String("provider-display-name", "", "Provider display name")
	flagSet.String("oidc-issuer-url", "", "OpenID Connect issuer URL (ie: https://accounts.google.com)")
	flagSet.Bool("insecure-oidc-allow-unverified-email", false, "Don't fail if an email address in an id_token is not verified")
	flagSet.Bool("insecure-oidc-skip-issuer-verification", false, "Do not verify if issuer matches OIDC discovery URL")
	flagSet.Bool("skip-oidc-discovery", false, "Skip OIDC discovery and use manually supplied Endpoints")
	flagSet.String("oidc-jwks-url", "", "OpenID Connect JWKS URL (ie: https://www.googleapis.com/oauth2/v3/certs)")
	flagSet.String("login-url", "", "Authentication endpoint")
	flagSet.String("redeem-url", "", "Token redemption endpoint")
	flagSet.String("profile-url", "", "Profile access endpoint")
	flagSet.String("resource", "", "The resource that is protected (Azure AD only)")
	flagSet.String("validate-url", "", "Access token validation endpoint")
	flagSet.String("scope", "", "OAuth scope specification")
	flagSet.String("prompt", "", "OIDC prompt")
	flagSet.String("approval-prompt", "force", "OAuth approval_prompt")

	flagSet.String("signature-key", "", "GAP-Signature request signature key (algorithm:secretkey)")
	flagSet.String("acr-values", "", "acr values string:  optional")
	flagSet.String("jwt-key", "", "private key in PEM format used to sign JWT, so that you can say something like -jwt-key=\"${OAUTH2_PROXY_JWT_KEY}\": required by login.gov")
	flagSet.String("jwt-key-file", "", "path to the private key file in PEM format used to sign the JWT so that you can say something like -jwt-key-file=/etc/ssl/private/jwt_signing_key.pem: required by login.gov")
	flagSet.String("pubjwk-url", "", "JWK pubkey access endpoint: required by login.gov")
	flagSet.Bool("gcp-healthchecks", false, "Enable GCP/GKE healthcheck endpoints")

	flagSet.String("user-id-claim", "email", "which claim contains the user ID")

	return flagSet
}
