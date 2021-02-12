package options

import (
	"crypto"
	"net/url"

	oidc "github.com/coreos/go-oidc"
	ipapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/ip"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
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
	ProxyPrefix        string   `flag:"proxy-prefix" cfg:"proxy_prefix"`
	PingPath           string   `flag:"ping-path" cfg:"ping_path"`
	PingUserAgent      string   `flag:"ping-user-agent" cfg:"ping_user_agent"`
	HTTPAddress        string   `flag:"http-address" cfg:"http_address"`
	HTTPSAddress       string   `flag:"https-address" cfg:"https_address"`
	ReverseProxy       bool     `flag:"reverse-proxy" cfg:"reverse_proxy"`
	RealClientIPHeader string   `flag:"real-client-ip-header" cfg:"real_client_ip_header"`
	TrustedIPs         []string `flag:"trusted-ip" cfg:"trusted_ips"`
	ForceHTTPS         bool     `flag:"force-https" cfg:"force_https"`
	RawRedirectURL     string   `flag:"redirect-url" cfg:"redirect_url"`
	ClientID           string   `flag:"client-id" cfg:"client_id"`
	ClientSecret       string   `flag:"client-secret" cfg:"client_secret"`
	ClientSecretFile   string   `flag:"client-secret-file" cfg:"client_secret_file"`
	TLSCertFile        string   `flag:"tls-cert-file" cfg:"tls_cert_file"`
	TLSKeyFile         string   `flag:"tls-key-file" cfg:"tls_key_file"`

	AuthenticatedEmailsFile  string   `flag:"authenticated-emails-file" cfg:"authenticated_emails_file"`
	KeycloakGroups           []string `flag:"keycloak-group" cfg:"keycloak_groups"`
	AzureTenant              string   `flag:"azure-tenant" cfg:"azure_tenant"`
	BitbucketTeam            string   `flag:"bitbucket-team" cfg:"bitbucket_team"`
	BitbucketRepository      string   `flag:"bitbucket-repository" cfg:"bitbucket_repository"`
	EmailDomains             []string `flag:"email-domain" cfg:"email_domains"`
	WhitelistDomains         []string `flag:"whitelist-domain" cfg:"whitelist_domains"`
	GitHubOrg                string   `flag:"github-org" cfg:"github_org"`
	GitHubTeam               string   `flag:"github-team" cfg:"github_team"`
	GitHubRepo               string   `flag:"github-repo" cfg:"github_repo"`
	GitHubToken              string   `flag:"github-token" cfg:"github_token"`
	GitHubUsers              []string `flag:"github-user" cfg:"github_users"`
	GitLabGroup              []string `flag:"gitlab-group" cfg:"gitlab_groups"`
	GitlabProjects           []string `flag:"gitlab-project" cfg:"gitlab_projects"`
	GoogleGroups             []string `flag:"google-group" cfg:"google_group"`
	GoogleAdminEmail         string   `flag:"google-admin-email" cfg:"google_admin_email"`
	GoogleServiceAccountJSON string   `flag:"google-service-account-json" cfg:"google_service_account_json"`
	HtpasswdFile             string   `flag:"htpasswd-file" cfg:"htpasswd_file"`

	Cookie    Cookie         `cfg:",squash"`
	Session   SessionOptions `cfg:",squash"`
	Logging   Logging        `cfg:",squash"`
	Templates Templates      `cfg:",squash"`

	// Not used in the legacy config, name not allowed to match an external key (upstreams)
	// TODO(JoelSpeed): Rename when legacy config is removed
	UpstreamServers Upstreams `cfg:",internal"`

	InjectRequestHeaders  []Header `cfg:",internal"`
	InjectResponseHeaders []Header `cfg:",internal"`

	SkipAuthRegex         []string `flag:"skip-auth-regex" cfg:"skip_auth_regex"`
	SkipAuthRoutes        []string `flag:"skip-auth-route" cfg:"skip_auth_routes"`
	SkipJwtBearerTokens   bool     `flag:"skip-jwt-bearer-tokens" cfg:"skip_jwt_bearer_tokens"`
	ExtraJwtIssuers       []string `flag:"extra-jwt-issuers" cfg:"extra_jwt_issuers"`
	SkipProviderButton    bool     `flag:"skip-provider-button" cfg:"skip_provider_button"`
	SSLInsecureSkipVerify bool     `flag:"ssl-insecure-skip-verify" cfg:"ssl_insecure_skip_verify"`
	SkipAuthPreflight     bool     `flag:"skip-auth-preflight" cfg:"skip_auth_preflight"`

	// These options allow for other providers besides Google, with
	// potential overrides.
	ProviderType                       string   `flag:"provider" cfg:"provider"`
	ProviderName                       string   `flag:"provider-display-name" cfg:"provider_display_name"`
	ProviderCAFiles                    []string `flag:"provider-ca-file" cfg:"provider_ca_files"`
	OIDCIssuerURL                      string   `flag:"oidc-issuer-url" cfg:"oidc_issuer_url"`
	InsecureOIDCAllowUnverifiedEmail   bool     `flag:"insecure-oidc-allow-unverified-email" cfg:"insecure_oidc_allow_unverified_email"`
	InsecureOIDCSkipIssuerVerification bool     `flag:"insecure-oidc-skip-issuer-verification" cfg:"insecure_oidc_skip_issuer_verification"`
	SkipOIDCDiscovery                  bool     `flag:"skip-oidc-discovery" cfg:"skip_oidc_discovery"`
	OIDCJwksURL                        string   `flag:"oidc-jwks-url" cfg:"oidc_jwks_url"`
	OIDCEmailClaim                     string   `flag:"oidc-email-claim" cfg:"oidc_email_claim"`
	OIDCGroupsClaim                    string   `flag:"oidc-groups-claim" cfg:"oidc_groups_claim"`
	LoginURL                           string   `flag:"login-url" cfg:"login_url"`
	RedeemURL                          string   `flag:"redeem-url" cfg:"redeem_url"`
	ProfileURL                         string   `flag:"profile-url" cfg:"profile_url"`
	ProtectedResource                  string   `flag:"resource" cfg:"resource"`
	ValidateURL                        string   `flag:"validate-url" cfg:"validate_url"`
	Scope                              string   `flag:"scope" cfg:"scope"`
	Prompt                             string   `flag:"prompt" cfg:"prompt"`
	ApprovalPrompt                     string   `flag:"approval-prompt" cfg:"approval_prompt"` // Deprecated by OIDC 1.0
	UserIDClaim                        string   `flag:"user-id-claim" cfg:"user_id_claim"`
	AllowedGroups                      []string `flag:"allowed-group" cfg:"allowed_groups"`

	SignatureKey    string `flag:"signature-key" cfg:"signature_key"`
	AcrValues       string `flag:"acr-values" cfg:"acr_values"`
	JWTKey          string `flag:"jwt-key" cfg:"jwt_key"`
	JWTKeyFile      string `flag:"jwt-key-file" cfg:"jwt_key_file"`
	PubJWKURL       string `flag:"pubjwk-url" cfg:"pubjwk_url"`
	GCPHealthChecks bool   `flag:"gcp-healthchecks" cfg:"gcp_healthchecks"`

	// internal values that are set after config validation
	redirectURL        *url.URL
	provider           providers.Provider
	signatureData      *SignatureData
	oidcVerifier       *oidc.IDTokenVerifier
	jwtBearerVerifiers []*oidc.IDTokenVerifier
	realClientIPParser ipapi.RealClientIPParser
}

// Options for Getting internal values
func (o *Options) GetRedirectURL() *url.URL                        { return o.redirectURL }
func (o *Options) GetProvider() providers.Provider                 { return o.provider }
func (o *Options) GetSignatureData() *SignatureData                { return o.signatureData }
func (o *Options) GetOIDCVerifier() *oidc.IDTokenVerifier          { return o.oidcVerifier }
func (o *Options) GetJWTBearerVerifiers() []*oidc.IDTokenVerifier  { return o.jwtBearerVerifiers }
func (o *Options) GetRealClientIPParser() ipapi.RealClientIPParser { return o.realClientIPParser }

// Options for Setting internal values
func (o *Options) SetRedirectURL(s *url.URL)                        { o.redirectURL = s }
func (o *Options) SetProvider(s providers.Provider)                 { o.provider = s }
func (o *Options) SetSignatureData(s *SignatureData)                { o.signatureData = s }
func (o *Options) SetOIDCVerifier(s *oidc.IDTokenVerifier)          { o.oidcVerifier = s }
func (o *Options) SetJWTBearerVerifiers(s []*oidc.IDTokenVerifier)  { o.jwtBearerVerifiers = s }
func (o *Options) SetRealClientIPParser(s ipapi.RealClientIPParser) { o.realClientIPParser = s }

// NewOptions constructs a new Options with defaulted values
func NewOptions() *Options {
	return &Options{
		ProxyPrefix:        "/oauth2",
		ProviderType:       "google",
		PingPath:           "/ping",
		HTTPAddress:        "127.0.0.1:4180",
		HTTPSAddress:       ":443",
		RealClientIPHeader: "X-Real-IP",
		ForceHTTPS:         false,

		Cookie:                           cookieDefaults(),
		Session:                          sessionOptionsDefaults(),
		Templates:                        templatesDefaults(),
		AzureTenant:                      "common",
		SkipAuthPreflight:                false,
		Prompt:                           "", // Change to "login" when ApprovalPrompt officially deprecated
		ApprovalPrompt:                   "force",
		InsecureOIDCAllowUnverifiedEmail: false,
		SkipOIDCDiscovery:                false,
		Logging:                          loggingDefaults(),
		UserIDClaim:                      providers.OIDCEmailClaim, // Deprecated: Use OIDCEmailClaim
		OIDCEmailClaim:                   providers.OIDCEmailClaim,
		OIDCGroupsClaim:                  providers.OIDCGroupsClaim,
	}
}

// NewFlagSet creates a new FlagSet with all of the flags required by Options
func NewFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("oauth2-proxy", pflag.ExitOnError)

	flagSet.String("http-address", "127.0.0.1:4180", "[http://]<addr>:<port> or unix://<path> to listen on for HTTP clients")
	flagSet.String("https-address", ":443", "<addr>:<port> to listen on for HTTPS clients")
	flagSet.Bool("reverse-proxy", false, "are we running behind a reverse proxy, controls whether headers like X-Real-Ip are accepted")
	flagSet.String("real-client-ip-header", "X-Real-IP", "Header used to determine the real IP of the client (one of: X-Forwarded-For, X-Real-IP, or X-ProxyUser-IP)")
	flagSet.StringSlice("trusted-ip", []string{}, "list of IPs or CIDR ranges to allow to bypass authentication. WARNING: trusting by IP has inherent security flaws, read the configuration documentation for more information.")
	flagSet.Bool("force-https", false, "force HTTPS redirect for HTTP requests")
	flagSet.String("tls-cert-file", "", "path to certificate file")
	flagSet.String("tls-key-file", "", "path to private key file")
	flagSet.String("redirect-url", "", "the OAuth Redirect URL. ie: \"https://internalapp.yourcompany.com/oauth2/callback\"")
	flagSet.StringSlice("skip-auth-regex", []string{}, "(DEPRECATED for --skip-auth-route) bypass authentication for requests path's that match (may be given multiple times)")
	flagSet.StringSlice("skip-auth-route", []string{}, "bypass authentication for requests that match the method & path. Format: method=path_regex OR path_regex alone for all methods")
	flagSet.Bool("skip-provider-button", false, "will skip sign-in-page to directly reach the next step: oauth/start")
	flagSet.Bool("skip-auth-preflight", false, "will skip authentication for OPTIONS requests")
	flagSet.Bool("ssl-insecure-skip-verify", false, "skip validation of certificates presented when using HTTPS providers")
	flagSet.Bool("skip-jwt-bearer-tokens", false, "will skip requests that have verified JWT bearer tokens (default false)")
	flagSet.StringSlice("extra-jwt-issuers", []string{}, "if skip-jwt-bearer-tokens is set, a list of extra JWT issuer=audience pairs (where the issuer URL has a .well-known/openid-configuration or a .well-known/jwks.json)")

	flagSet.StringSlice("email-domain", []string{}, "authenticate emails with the specified domain (may be given multiple times). Use * to authenticate any email")
	flagSet.StringSlice("whitelist-domain", []string{}, "allowed domains for redirection after authentication. Prefix domain with a . to allow subdomains (eg .example.com)")
	flagSet.StringSlice("keycloak-group", []string{}, "restrict logins to members of these groups (may be given multiple times)")
	flagSet.String("azure-tenant", "common", "go to a tenant-specific or common (tenant-independent) endpoint.")
	flagSet.String("bitbucket-team", "", "restrict logins to members of this team")
	flagSet.String("bitbucket-repository", "", "restrict logins to user with access to this repository")
	flagSet.String("github-org", "", "restrict logins to members of this organisation")
	flagSet.String("github-team", "", "restrict logins to members of this team")
	flagSet.String("github-repo", "", "restrict logins to collaborators of this repository")
	flagSet.String("github-token", "", "the token to use when verifying repository collaborators (must have push access to the repository)")
	flagSet.StringSlice("github-user", []string{}, "allow users with these usernames to login even if they do not belong to the specified org and team or collaborators (may be given multiple times)")
	flagSet.StringSlice("gitlab-group", []string{}, "restrict logins to members of this group (may be given multiple times)")
	flagSet.StringSlice("gitlab-project", []string{}, "restrict logins to members of this project (may be given multiple times) (eg `group/project=accesslevel`). Access level should be a value matching Gitlab access levels (see https://docs.gitlab.com/ee/api/members.html#valid-access-levels), defaulted to 20 if absent")
	flagSet.StringSlice("google-group", []string{}, "restrict logins to members of this google group (may be given multiple times).")
	flagSet.String("google-admin-email", "", "the google admin to impersonate for api calls")
	flagSet.String("google-service-account-json", "", "the path to the service account json credentials")
	flagSet.String("client-id", "", "the OAuth Client ID: ie: \"123456.apps.googleusercontent.com\"")
	flagSet.String("client-secret", "", "the OAuth Client Secret")
	flagSet.String("client-secret-file", "", "the file with OAuth Client Secret")
	flagSet.String("authenticated-emails-file", "", "authenticate against emails via file (one per line)")
	flagSet.String("htpasswd-file", "", "additionally authenticate against a htpasswd file. Entries must be created with \"htpasswd -B\" for bcrypt encryption")
	flagSet.String("proxy-prefix", "/oauth2", "the url root path that this proxy should be nested under (e.g. /<oauth2>/sign_in)")
	flagSet.String("ping-path", "/ping", "the ping endpoint that can be used for basic health checks")
	flagSet.String("ping-user-agent", "", "special User-Agent that will be used for basic health checks")
	flagSet.String("session-store-type", "cookie", "the session storage provider to use")
	flagSet.Bool("session-cookie-minimal", false, "strip OAuth tokens from cookie session stores if they aren't needed (cookie session store only)")
	flagSet.String("redis-connection-url", "", "URL of redis server for redis session storage (eg: redis://HOST[:PORT])")
	flagSet.String("redis-password", "", "Redis password. Applicable for all Redis configurations. Will override any password set in `--redis-connection-url`")
	flagSet.Bool("redis-use-sentinel", false, "Connect to redis via sentinels. Must set --redis-sentinel-master-name and --redis-sentinel-connection-urls to use this feature")
	flagSet.String("redis-sentinel-password", "", "Redis sentinel password. Used only for sentinel connection; any redis node passwords need to use `--redis-password`")
	flagSet.String("redis-sentinel-master-name", "", "Redis sentinel master name. Used in conjunction with --redis-use-sentinel")
	flagSet.String("redis-ca-path", "", "Redis custom CA path")
	flagSet.Bool("redis-insecure-skip-tls-verify", false, "Use insecure TLS connection to redis")
	flagSet.StringSlice("redis-sentinel-connection-urls", []string{}, "List of Redis sentinel connection URLs (eg redis://HOST[:PORT]). Used in conjunction with --redis-use-sentinel")
	flagSet.Bool("redis-use-cluster", false, "Connect to redis cluster. Must set --redis-cluster-connection-urls to use this feature")
	flagSet.StringSlice("redis-cluster-connection-urls", []string{}, "List of Redis cluster connection URLs (eg redis://HOST[:PORT]). Used in conjunction with --redis-use-cluster")

	flagSet.String("provider", "google", "OAuth provider")
	flagSet.String("provider-display-name", "", "Provider display name")
	flagSet.StringSlice("provider-ca-file", []string{}, "One or more paths to CA certificates that should be used when connecting to the provider.  If not specified, the default Go trust sources are used instead.")
	flagSet.String("oidc-issuer-url", "", "OpenID Connect issuer URL (ie: https://accounts.google.com)")
	flagSet.Bool("insecure-oidc-allow-unverified-email", false, "Don't fail if an email address in an id_token is not verified")
	flagSet.Bool("insecure-oidc-skip-issuer-verification", false, "Do not verify if issuer matches OIDC discovery URL")
	flagSet.Bool("skip-oidc-discovery", false, "Skip OIDC discovery and use manually supplied Endpoints")
	flagSet.String("oidc-jwks-url", "", "OpenID Connect JWKS URL (ie: https://www.googleapis.com/oauth2/v3/certs)")
	flagSet.String("oidc-groups-claim", providers.OIDCGroupsClaim, "which OIDC claim contains the user groups")
	flagSet.String("oidc-email-claim", providers.OIDCEmailClaim, "which OIDC claim contains the user's email")
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

	flagSet.String("user-id-claim", providers.OIDCEmailClaim, "(DEPRECATED for `oidc-email-claim`) which claim contains the user ID")
	flagSet.StringSlice("allowed-group", []string{}, "restrict logins to members of this group (may be given multiple times)")

	flagSet.AddFlagSet(cookieFlagSet())
	flagSet.AddFlagSet(loggingFlagSet())
	flagSet.AddFlagSet(templatesFlagSet())

	return flagSet
}
