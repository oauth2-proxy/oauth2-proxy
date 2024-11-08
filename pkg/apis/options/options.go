package options

import (
	"crypto"
	"net/url"

	ipapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/ip"
	internaloidc "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/providers/oidc"
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
	ProxyPrefix         string   `flag:"proxy-prefix" cfg:"proxy_prefix"`
	PingPath            string   `flag:"ping-path" cfg:"ping_path"`
	PingUserAgent       string   `flag:"ping-user-agent" cfg:"ping_user_agent"`
	ReadyPath           string   `flag:"ready-path" cfg:"ready_path"`
	ReverseProxy        bool     `flag:"reverse-proxy" cfg:"reverse_proxy"`
	RealClientIPHeader  string   `flag:"real-client-ip-header" cfg:"real_client_ip_header"`
	TrustedIPs          []string `flag:"trusted-ip" cfg:"trusted_ips"`
	ForceHTTPS          bool     `flag:"force-https" cfg:"force_https"`
	RawRedirectURL      string   `flag:"redirect-url" cfg:"redirect_url"`
	RelativeRedirectURL bool     `flag:"relative-redirect-url" cfg:"relative_redirect_url"`

	AuthenticatedEmailsFile string   `flag:"authenticated-emails-file" cfg:"authenticated_emails_file"`
	EmailDomains            []string `flag:"email-domain" cfg:"email_domains"`
	WhitelistDomains        []string `flag:"whitelist-domain" cfg:"whitelist_domains"`
	HtpasswdFile            string   `flag:"htpasswd-file" cfg:"htpasswd_file"`
	HtpasswdUserGroups      []string `flag:"htpasswd-user-group" cfg:"htpasswd_user_groups"`

	Cookie    Cookie         `cfg:",squash"`
	Session   SessionOptions `cfg:",squash"`
	Logging   Logging        `cfg:",squash"`
	Templates Templates      `cfg:",squash"`

	// Not used in the legacy config, name not allowed to match an external key (upstreams)
	// TODO(JoelSpeed): Rename when legacy config is removed
	UpstreamServers UpstreamConfig `cfg:",internal"`

	InjectRequestHeaders  []Header `cfg:",internal"`
	InjectResponseHeaders []Header `cfg:",internal"`

	Server        Server `cfg:",internal"`
	MetricsServer Server `cfg:",internal"`

	Providers Providers `cfg:",internal"`

	APIRoutes             []string `flag:"api-route" cfg:"api_routes"`
	SkipAuthRegex         []string `flag:"skip-auth-regex" cfg:"skip_auth_regex"`
	SkipAuthRoutes        []string `flag:"skip-auth-route" cfg:"skip_auth_routes"`
	SkipJwtBearerTokens   bool     `flag:"skip-jwt-bearer-tokens" cfg:"skip_jwt_bearer_tokens"`
	ExtraJwtIssuers       []string `flag:"extra-jwt-issuers" cfg:"extra_jwt_issuers"`
	SkipProviderButton    bool     `flag:"skip-provider-button" cfg:"skip_provider_button"`
	SSLInsecureSkipVerify bool     `flag:"ssl-insecure-skip-verify" cfg:"ssl_insecure_skip_verify"`
	SkipAuthPreflight     bool     `flag:"skip-auth-preflight" cfg:"skip_auth_preflight"`
	ForceJSONErrors       bool     `flag:"force-json-errors" cfg:"force_json_errors"`
	EncodeState           bool     `flag:"encode-state" cfg:"encode_state"`
	AllowQuerySemicolons  bool     `flag:"allow-query-semicolons" cfg:"allow_query_semicolons"`

	SignatureKey    string `flag:"signature-key" cfg:"signature_key"`
	GCPHealthChecks bool   `flag:"gcp-healthchecks" cfg:"gcp_healthchecks"`

	// This is used for backwards compatibility for basic auth users
	LegacyPreferEmailToUser bool `cfg:",internal"`

	// internal values that are set after config validation
	redirectURL        *url.URL
	signatureData      *SignatureData
	oidcVerifier       internaloidc.IDTokenVerifier
	jwtBearerVerifiers []internaloidc.IDTokenVerifier
	realClientIPParser ipapi.RealClientIPParser
}

// Options for Getting internal values
func (o *Options) GetRedirectURL() *url.URL                      { return o.redirectURL }
func (o *Options) GetSignatureData() *SignatureData              { return o.signatureData }
func (o *Options) GetOIDCVerifier() internaloidc.IDTokenVerifier { return o.oidcVerifier }
func (o *Options) GetJWTBearerVerifiers() []internaloidc.IDTokenVerifier {
	return o.jwtBearerVerifiers
}
func (o *Options) GetRealClientIPParser() ipapi.RealClientIPParser { return o.realClientIPParser }

// Options for Setting internal values
func (o *Options) SetRedirectURL(s *url.URL)                              { o.redirectURL = s }
func (o *Options) SetSignatureData(s *SignatureData)                      { o.signatureData = s }
func (o *Options) SetOIDCVerifier(s internaloidc.IDTokenVerifier)         { o.oidcVerifier = s }
func (o *Options) SetJWTBearerVerifiers(s []internaloidc.IDTokenVerifier) { o.jwtBearerVerifiers = s }
func (o *Options) SetRealClientIPParser(s ipapi.RealClientIPParser)       { o.realClientIPParser = s }

// NewOptions constructs a new Options with defaulted values
func NewOptions() *Options {
	return &Options{
		ProxyPrefix:        "/oauth2",
		Providers:          providerDefaults(),
		PingPath:           "/ping",
		ReadyPath:          "/ready",
		RealClientIPHeader: "X-Real-IP",
		ForceHTTPS:         false,
		Cookie:             cookieDefaults(),
		Session:            sessionOptionsDefaults(),
		Templates:          templatesDefaults(),
		SkipAuthPreflight:  false,
		Logging:            loggingDefaults(),
	}
}

// NewFlagSet creates a new FlagSet with all of the flags required by Options
func NewFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("oauth2-proxy", pflag.ExitOnError)

	flagSet.Bool("reverse-proxy", false, "are we running behind a reverse proxy, controls whether headers like X-Real-Ip are accepted")
	flagSet.String("real-client-ip-header", "X-Real-IP", "Header used to determine the real IP of the client (one of: X-Forwarded-For, X-Real-IP, X-ProxyUser-IP, X-Envoy-External-Address, or CF-Connecting-IP)")
	flagSet.StringSlice("trusted-ip", []string{}, "list of IPs or CIDR ranges to allow to bypass authentication. WARNING: trusting by IP has inherent security flaws, read the configuration documentation for more information.")
	flagSet.Bool("force-https", false, "force HTTPS redirect for HTTP requests")
	flagSet.String("redirect-url", "", "the OAuth Redirect URL. ie: \"https://internalapp.yourcompany.com/oauth2/callback\"")
	flagSet.Bool("relative-redirect-url", false, "allow relative OAuth Redirect URL.")
	flagSet.StringSlice("skip-auth-regex", []string{}, "(DEPRECATED for --skip-auth-route) bypass authentication for requests path's that match (may be given multiple times)")
	flagSet.StringSlice("skip-auth-route", []string{}, "bypass authentication for requests that match the method & path. Format: method=path_regex OR method!=path_regex. For all methods: path_regex OR !=path_regex")
	flagSet.StringSlice("api-route", []string{}, "return HTTP 401 instead of redirecting to authentication server if token is not valid. Format: path_regex")
	flagSet.Bool("skip-provider-button", false, "will skip sign-in-page to directly reach the next step: oauth/start")
	flagSet.Bool("skip-auth-preflight", false, "will skip authentication for OPTIONS requests")
	flagSet.Bool("ssl-insecure-skip-verify", false, "skip validation of certificates presented when using HTTPS providers")
	flagSet.Bool("skip-jwt-bearer-tokens", false, "will skip requests that have verified JWT bearer tokens (default false)")
	flagSet.Bool("force-json-errors", false, "will force JSON errors instead of HTTP error pages or redirects")
	flagSet.Bool("encode-state", false, "will encode oauth state with base64")
	flagSet.Bool("allow-query-semicolons", false, "allow the use of semicolons in query args")
	flagSet.StringSlice("extra-jwt-issuers", []string{}, "if skip-jwt-bearer-tokens is set, a list of extra JWT issuer=audience pairs (where the issuer URL has a .well-known/openid-configuration or a .well-known/jwks.json)")

	flagSet.StringSlice("email-domain", []string{}, "authenticate emails with the specified domain (may be given multiple times). Use * to authenticate any email")
	flagSet.StringSlice("whitelist-domain", []string{}, "allowed domains for redirection after authentication. Prefix domain with a . or a *. to allow subdomains (eg .example.com, *.example.com)")
	flagSet.String("authenticated-emails-file", "", "authenticate against emails via file (one per line)")
	flagSet.String("htpasswd-file", "", "additionally authenticate against a htpasswd file. Entries must be created with \"htpasswd -B\" for bcrypt encryption")
	flagSet.StringSlice("htpasswd-user-group", []string{}, "the groups to be set on sessions for htpasswd users (may be given multiple times)")
	flagSet.String("proxy-prefix", "/oauth2", "the url root path that this proxy should be nested under (e.g. /<oauth2>/sign_in)")
	flagSet.String("ping-path", "/ping", "the ping endpoint that can be used for basic health checks")
	flagSet.String("ping-user-agent", "", "special User-Agent that will be used for basic health checks")
	flagSet.String("ready-path", "/ready", "the ready endpoint that can be used for deep health checks")
	flagSet.String("session-store-type", "cookie", "the session storage provider to use")
	flagSet.Bool("session-cookie-minimal", false, "strip OAuth tokens from cookie session stores if they aren't needed (cookie session store only)")
	flagSet.String("redis-connection-url", "", "URL of redis server for redis session storage (eg: redis://[USER[:PASSWORD]@]HOST[:PORT])")
	flagSet.String("redis-username", "", "Redis username. Applicable for Redis configurations where ACL has been configured. Will override any username set in `--redis-connection-url`")
	flagSet.String("redis-password", "", "Redis password. Applicable for all Redis configurations. Will override any password set in `--redis-connection-url`")
	flagSet.Bool("redis-use-sentinel", false, "Connect to redis via sentinels. Must set --redis-sentinel-master-name and --redis-sentinel-connection-urls to use this feature")
	flagSet.String("redis-sentinel-password", "", "Redis sentinel password. Used only for sentinel connection; any redis node passwords need to use `--redis-password`")
	flagSet.String("redis-sentinel-master-name", "", "Redis sentinel master name. Used in conjunction with --redis-use-sentinel")
	flagSet.String("redis-ca-path", "", "Redis custom CA path")
	flagSet.Bool("redis-insecure-skip-tls-verify", false, "Use insecure TLS connection to redis")
	flagSet.StringSlice("redis-sentinel-connection-urls", []string{}, "List of Redis sentinel connection URLs (eg redis://[USER[:PASSWORD]@]HOST[:PORT]). Used in conjunction with --redis-use-sentinel")
	flagSet.Bool("redis-use-cluster", false, "Connect to redis cluster. Must set --redis-cluster-connection-urls to use this feature")
	flagSet.StringSlice("redis-cluster-connection-urls", []string{}, "List of Redis cluster connection URLs (eg redis://[USER[:PASSWORD]@]HOST[:PORT]). Used in conjunction with --redis-use-cluster")
	flagSet.Int("redis-connection-idle-timeout", 0, "Redis connection idle timeout seconds, if Redis timeout option is non-zero, the --redis-connection-idle-timeout must be less then Redis timeout option")
	flagSet.String("signature-key", "", "GAP-Signature request signature key (algorithm:secretkey)")
	flagSet.Bool("gcp-healthchecks", false, "Enable GCP/GKE healthcheck endpoints")

	flagSet.AddFlagSet(cookieFlagSet())
	flagSet.AddFlagSet(loggingFlagSet())
	flagSet.AddFlagSet(templatesFlagSet())

	return flagSet
}
