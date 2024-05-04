package options

import (
	"github.com/spf13/pflag"
)

type LegacyProxyOptions struct {
	AllowQuerySemicolons    bool     `flag:"allow-query-semicolons" cfg:"allow_query_semicolons"`
	ProxyPrefix             string   `flag:"proxy-prefix" cfg:"proxy_prefix"`
	RealClientIPHeader      string   `flag:"real-client-ip-header" cfg:"real_client_ip_header"`
	ReverseProxy            bool     `flag:"reverse-proxy" cfg:"reverse_proxy"`
	TrustedIPs              []string `flag:"trusted-ip" cfg:"trusted_ips"`
	ForceHTTPS              bool     `flag:"force-https" cfg:"force_https"`
	SSLInsecureSkipVerify   bool     `flag:"ssl-insecure-skip-verify" cfg:"ssl_insecure_skip_verify"`
	ForceJSONErrors         bool     `flag:"force-json-errors" cfg:"force_json_errors"`
	SkipAuthRegex           []string `flag:"skip-auth-regex" cfg:"skip_auth_regex"`
	SkipAuthRoutes          []string `flag:"skip-auth-route" cfg:"skip_auth_routes"`
	AuthenticatedEmailsFile string   `flag:"authenticated-emails-file" cfg:"authenticated_emails_file"`
	EmailDomains            []string `flag:"email-domain" cfg:"email_domains"`
	WhitelistDomains        []string `flag:"whitelist-domain" cfg:"whitelist_domains"`
	HtpasswdFile            string   `flag:"htpasswd-file" cfg:"htpasswd_file"`
	HtpasswdUserGroups      []string `flag:"htpasswd-user-group" cfg:"htpasswd_user_groups"`
	RawRedirectURL          string   `flag:"redirect-url" cfg:"redirect_url"`
	RelativeRedirectURL     bool     `flag:"relative-redirect-url" cfg:"relative_redirect_url"`
	APIRoutes               []string `flag:"api-route" cfg:"api_routes"`
	SkipJwtBearerTokens     bool     `flag:"skip-jwt-bearer-tokens" cfg:"skip_jwt_bearer_tokens"`
	ExtraJwtIssuers         []string `flag:"extra-jwt-issuers" cfg:"extra_jwt_issuers"`
	SkipProviderButton      bool     `flag:"skip-provider-button" cfg:"skip_provider_button"`
	SkipAuthPreflight       bool     `flag:"skip-auth-preflight" cfg:"skip_auth_preflight"`
	SignatureKey            string   `flag:"signature-key" cfg:"signature_key"`
	EncodeState             bool     `flag:"encode-state" cfg:"encode_state"`
}

func legacyProxyOptionsFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("proxy", pflag.ExitOnError)
	flagSet.Bool("reverse-proxy", false, "are we running behind a reverse proxy, controls whether headers like X-Real-Ip are accepted")
	flagSet.String("real-client-ip-header", "X-Real-IP", "Header used to determine the real IP of the client (one of: X-Forwarded-For, X-Real-IP, or X-ProxyUser-IP)")
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
	flagSet.Bool("allow-query-semicolons", false, "allow the use of semicolons in query args")
	flagSet.StringSlice("extra-jwt-issuers", []string{}, "if skip-jwt-bearer-tokens is set, a list of extra JWT issuer=audience pairs (where the issuer URL has a .well-known/openid-configuration or a .well-known/jwks.json)")

	flagSet.StringSlice("email-domain", []string{}, "authenticate emails with the specified domain (may be given multiple times). Use * to authenticate any email")
	flagSet.StringSlice("whitelist-domain", []string{}, "allowed domains for redirection after authentication. Prefix domain with a . or a *. to allow subdomains (eg .example.com, *.example.com)")
	flagSet.String("authenticated-emails-file", "", "authenticate against emails via file (one per line)")
	flagSet.String("htpasswd-file", "", "additionally authenticate against a htpasswd file. Entries must be created with \"htpasswd -B\" for bcrypt encryption")
	flagSet.StringSlice("htpasswd-user-group", []string{}, "the groups to be set on sessions for htpasswd users (may be given multiple times)")
	flagSet.String("proxy-prefix", "/oauth2", "the url root path that this proxy should be nested under (e.g. /<oauth2>/sign_in)")

	flagSet.Bool("encode-state", false, "will encode oauth state with base64")

	flagSet.String("signature-key", "", "GAP-Signature request signature key (algorithm:secretkey)")
	return flagSet
}

func (l *LegacyProxyOptions) convert() ProxyOptions {
	return ProxyOptions{
		// security
		AllowQuerySemicolons:  l.AllowQuerySemicolons,
		ForceHTTPS:            l.ForceHTTPS,
		SkipAuthRegex:         l.SkipAuthRegex,
		SkipAuthRoutes:        l.SkipAuthRoutes,
		SkipAuthPreflight:     l.SkipAuthPreflight,
		SSLInsecureSkipVerify: l.SSLInsecureSkipVerify,
		TrustedIPs:            l.TrustedIPs,

		// authentication
		AuthenticatedEmailsFile: l.AuthenticatedEmailsFile,
		EmailDomains:            l.EmailDomains,
		WhitelistDomains:        l.WhitelistDomains,
		HtpasswdFile:            l.HtpasswdFile,
		HtpasswdUserGroups:      l.HtpasswdUserGroups,
		SkipJwtBearerTokens:     l.SkipJwtBearerTokens,
		ExtraJwtIssuers:         l.ExtraJwtIssuers,
		ForceJSONErrors:         l.ForceJSONErrors,

		// routing
		APIRoutes:           l.APIRoutes,
		ReverseProxy:        l.ReverseProxy,
		ProxyPrefix:         l.ProxyPrefix,
		RedirectURL:         l.RawRedirectURL,
		RelativeRedirectURL: l.RelativeRedirectURL,
		RealClientIPHeader:  l.RealClientIPHeader,
		SkipProviderButton:  l.SkipProviderButton,
		EncodeState:         l.EncodeState,

		LegacySignatureKey: l.SignatureKey,
	}
}
