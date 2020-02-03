package main

import (
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	options "github.com/mreiferson/go-options"
	"github.com/pusher/oauth2_proxy/pkg/logger"
)

func main() {
	logger.SetFlags(logger.Lshortfile)
	flagSet := flag.NewFlagSet("oauth2_proxy", flag.ExitOnError)

	emailDomains := StringArray{}
	whitelistDomains := StringArray{}
	upstreams := StringArray{}
	skipAuthRegex := StringArray{}
	jwtIssuers := StringArray{}
	googleGroups := StringArray{}
	redisSentinelConnectionURLs := StringArray{}

	config := flagSet.String("config", "", "path to config file")
	showVersion := flagSet.Bool("version", false, "print version string")

	flagSet.String("http-address", "127.0.0.1:4180", "[http://]<addr>:<port> or unix://<path> to listen on for HTTP clients")
	flagSet.String("https-address", ":443", "<addr>:<port> to listen on for HTTPS clients")
	flagSet.Bool("reverse-proxy", false, "are we running behind a reverse proxy, controls whether headers like X-Real-Ip are accepted")
	flagSet.Bool("force-https", false, "force HTTPS redirect for HTTP requests")
	flagSet.String("tls-cert-file", "", "path to certificate file")
	flagSet.String("tls-key-file", "", "path to private key file")
	flagSet.String("redirect-url", "", "the OAuth Redirect URL. ie: \"https://internalapp.yourcompany.com/oauth2/callback\"")
	flagSet.Bool("set-xauthrequest", false, "set X-Auth-Request-User and X-Auth-Request-Email response headers (useful in Nginx auth_request mode)")
	flagSet.Var(&upstreams, "upstream", "the http url(s) of the upstream endpoint, file:// paths for static files or static://<status_code> for static response. Routing is based on the path")
	flagSet.Bool("pass-basic-auth", true, "pass HTTP Basic Auth, X-Forwarded-User and X-Forwarded-Email information to upstream")
	flagSet.Bool("pass-user-headers", true, "pass X-Forwarded-User and X-Forwarded-Email information to upstream")
	flagSet.String("basic-auth-password", "", "the password to set when passing the HTTP Basic Auth header")
	flagSet.Bool("pass-access-token", false, "pass OAuth access_token to upstream via X-Forwarded-Access-Token header")
	flagSet.Bool("pass-host-header", true, "pass the request Host Header to upstream")
	flagSet.Bool("pass-authorization-header", false, "pass the Authorization Header to upstream")
	flagSet.Bool("set-authorization-header", false, "set Authorization response headers (useful in Nginx auth_request mode)")
	flagSet.Var(&skipAuthRegex, "skip-auth-regex", "bypass authentication for requests path's that match (may be given multiple times)")
	flagSet.Bool("skip-provider-button", false, "will skip sign-in-page to directly reach the next step: oauth/start")
	flagSet.Bool("skip-auth-preflight", false, "will skip authentication for OPTIONS requests")
	flagSet.Bool("ssl-insecure-skip-verify", false, "skip validation of certificates presented when using HTTPS providers")
	flagSet.Bool("ssl-upstream-insecure-skip-verify", false, "skip validation of certificates presented when using HTTPS upstreams")
	flagSet.Duration("flush-interval", time.Duration(1)*time.Second, "period between response flushing when streaming responses")
	flagSet.Bool("skip-jwt-bearer-tokens", false, "will skip requests that have verified JWT bearer tokens (default false)")
	flagSet.Var(&jwtIssuers, "extra-jwt-issuers", "if skip-jwt-bearer-tokens is set, a list of extra JWT issuer=audience pairs (where the issuer URL has a .well-known/openid-configuration or a .well-known/jwks.json)")

	flagSet.Var(&emailDomains, "email-domain", "authenticate emails with the specified domain (may be given multiple times). Use * to authenticate any email")
	flagSet.Var(&whitelistDomains, "whitelist-domain", "allowed domains for redirection after authentication. Prefix domain with a . to allow subdomains (eg .example.com)")
	flagSet.String("keycloak-group", "", "restrict login to members of this group.")
	flagSet.String("azure-tenant", "common", "go to a tenant-specific or common (tenant-independent) endpoint.")
	flagSet.String("bitbucket-team", "", "restrict logins to members of this team")
	flagSet.String("bitbucket-repository", "", "restrict logins to user with access to this repository")
	flagSet.String("github-org", "", "restrict logins to members of this organisation")
	flagSet.String("github-team", "", "restrict logins to members of this team")
	flagSet.String("gitlab-group", "", "restrict logins to members of this group")
	flagSet.Var(&googleGroups, "google-group", "restrict logins to members of this google group (may be given multiple times).")
	flagSet.String("google-admin-email", "", "the google admin to impersonate for api calls")
	flagSet.String("google-service-account-json", "", "the path to the service account json credentials")
	flagSet.String("client-id", "", "the OAuth Client ID: ie: \"123456.apps.googleusercontent.com\"")
	flagSet.String("client-secret", "", "the OAuth Client Secret")
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
	flagSet.String("cookie-domain", "", "an optional cookie domain to force cookies to (ie: .yourcompany.com)*")
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
	flagSet.Var(&redisSentinelConnectionURLs, "redis-sentinel-connection-urls", "List of Redis sentinel connection URLs (eg redis://HOST[:PORT]). Used in conjunction with --redis-use-sentinel")

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
	flagSet.Bool("skip-oidc-discovery", false, "Skip OIDC discovery and use manually supplied Endpoints")
	flagSet.String("oidc-jwks-url", "", "OpenID Connect JWKS URL (ie: https://www.googleapis.com/oauth2/v3/certs)")
	flagSet.String("login-url", "", "Authentication endpoint")
	flagSet.String("redeem-url", "", "Token redemption endpoint")
	flagSet.String("profile-url", "", "Profile access endpoint")
	flagSet.String("resource", "", "The resource that is protected (Azure AD only)")
	flagSet.String("validate-url", "", "Access token validation endpoint")
	flagSet.String("scope", "", "OAuth scope specification")
	flagSet.String("approval-prompt", "force", "OAuth approval_prompt")

	flagSet.String("signature-key", "", "GAP-Signature request signature key (algorithm:secretkey)")
	flagSet.String("acr-values", "http://idmanagement.gov/ns/assurance/loa/1", "acr values string:  optional, used by login.gov")
	flagSet.String("jwt-key", "", "private key in PEM format used to sign JWT, so that you can say something like -jwt-key=\"${OAUTH2_PROXY_JWT_KEY}\": required by login.gov")
	flagSet.String("jwt-key-file", "", "path to the private key file in PEM format used to sign the JWT so that you can say something like -jwt-key-file=/etc/ssl/private/jwt_signing_key.pem: required by login.gov")
	flagSet.String("pubjwk-url", "", "JWK pubkey access endpoint: required by login.gov")
	flagSet.Bool("gcp-healthchecks", false, "Enable GCP/GKE healthcheck endpoints")

	flagSet.Parse(os.Args[1:])

	if *showVersion {
		fmt.Printf("oauth2_proxy %s (built with %s)\n", VERSION, runtime.Version())
		return
	}

	opts := NewOptions()

	cfg := make(EnvOptions)
	if *config != "" {
		_, err := toml.DecodeFile(*config, &cfg)
		if err != nil {
			logger.Fatalf("ERROR: failed to load config file %s - %s", *config, err)
		}
	}
	cfg.LoadEnvForStruct(opts)
	options.Resolve(opts, flagSet, cfg)

	err := opts.Validate()
	if err != nil {
		logger.Printf("%s", err)
		os.Exit(1)
	}

	validator := NewValidator(opts.EmailDomains, opts.AuthenticatedEmailsFile)
	oauthproxy := NewOAuthProxy(opts, validator)

	if len(opts.Banner) >= 1 {
		if opts.Banner == "-" {
			oauthproxy.SignInMessage = ""
		} else {
			oauthproxy.SignInMessage = opts.Banner
		}
	} else if len(opts.EmailDomains) != 0 && opts.AuthenticatedEmailsFile == "" {
		if len(opts.EmailDomains) > 1 {
			oauthproxy.SignInMessage = fmt.Sprintf("Authenticate using one of the following domains: %v", strings.Join(opts.EmailDomains, ", "))
		} else if opts.EmailDomains[0] != "*" {
			oauthproxy.SignInMessage = fmt.Sprintf("Authenticate using %v", opts.EmailDomains[0])
		}
	}

	if opts.HtpasswdFile != "" {
		logger.Printf("using htpasswd file %s", opts.HtpasswdFile)
		oauthproxy.HtpasswdFile, err = NewHtpasswdFromFile(opts.HtpasswdFile)
		oauthproxy.DisplayHtpasswdForm = opts.DisplayHtpasswdForm
		if err != nil {
			logger.Fatalf("FATAL: unable to open %s %s", opts.HtpasswdFile, err)
		}
	}

	rand.Seed(time.Now().UnixNano())

	var handler http.Handler
	if opts.GCPHealthChecks {
		handler = redirectToHTTPS(opts, gcpHealthcheck(LoggingHandler(oauthproxy)))
	} else {
		handler = redirectToHTTPS(opts, LoggingHandler(oauthproxy))
	}
	s := &Server{
		Handler: handler,
		Opts:    opts,
	}
	s.ListenAndServe()
}
