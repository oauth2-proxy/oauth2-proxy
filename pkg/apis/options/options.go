package options

import (
	"crypto"
	"net/url"
	"regexp"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/logging"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/providers"
)

// SignatureData holds hmacauth signature hash and key
type SignatureData struct {
	Hash crypto.Hash
	Key  string
}

// Options holds Configuration Options that can be set by Command Line Flag,
// or Config File
type Options struct {
	ProxyPrefix        string `flag:"proxy-prefix" cfg:"proxy_prefix" env:"OAUTH2_PROXY_PROXY_PREFIX"`
	PingPath           string `flag:"ping-path" cfg:"ping_path" env:"OAUTH2_PROXY_PING_PATH"`
	ProxyWebSockets    bool   `flag:"proxy-websockets" cfg:"proxy_websockets" env:"OAUTH2_PROXY_PROXY_WEBSOCKETS"`
	HTTPAddress        string `flag:"http-address" cfg:"http_address" env:"OAUTH2_PROXY_HTTP_ADDRESS"`
	HTTPSAddress       string `flag:"https-address" cfg:"https_address" env:"OAUTH2_PROXY_HTTPS_ADDRESS"`
	ReverseProxy       bool   `flag:"reverse-proxy" cfg:"reverse_proxy" env:"OAUTH2_PROXY_REVERSE_PROXY"`
	RealClientIPHeader string `flag:"real-client-ip-header" cfg:"real_client_ip_header" env:"OAUTH2_PROXY_REAL_CLIENT_IP_HEADER"`
	ForceHTTPS         bool   `flag:"force-https" cfg:"force_https" env:"OAUTH2_PROXY_FORCE_HTTPS"`
	RawRedirectURL     string `flag:"redirect-url" cfg:"redirect_url" env:"OAUTH2_PROXY_REDIRECT_URL"`
	ClientID           string `flag:"client-id" cfg:"client_id" env:"OAUTH2_PROXY_CLIENT_ID"`
	ClientSecret       string `flag:"client-secret" cfg:"client_secret" env:"OAUTH2_PROXY_CLIENT_SECRET"`
	ClientSecretFile   string `flag:"client-secret-file" cfg:"client_secret_file" env:"OAUTH2_PROXY_CLIENT_SECRET_FILE"`
	TLSCertFile        string `flag:"tls-cert-file" cfg:"tls_cert_file" env:"OAUTH2_PROXY_TLS_CERT_FILE"`
	TLSKeyFile         string `flag:"tls-key-file" cfg:"tls_key_file" env:"OAUTH2_PROXY_TLS_KEY_FILE"`

	AuthenticatedEmailsFile  string   `flag:"authenticated-emails-file" cfg:"authenticated_emails_file" env:"OAUTH2_PROXY_AUTHENTICATED_EMAILS_FILE"`
	KeycloakGroup            string   `flag:"keycloak-group" cfg:"keycloak_group" env:"OAUTH2_PROXY_KEYCLOAK_GROUP"`
	AzureTenant              string   `flag:"azure-tenant" cfg:"azure_tenant" env:"OAUTH2_PROXY_AZURE_TENANT"`
	BitbucketTeam            string   `flag:"bitbucket-team" cfg:"bitbucket_team" env:"OAUTH2_PROXY_BITBUCKET_TEAM"`
	BitbucketRepository      string   `flag:"bitbucket-repository" cfg:"bitbucket_repository" env:"OAUTH2_PROXY_BITBUCKET_REPOSITORY"`
	EmailDomains             []string `flag:"email-domain" cfg:"email_domains" env:"OAUTH2_PROXY_EMAIL_DOMAINS"`
	WhitelistDomains         []string `flag:"whitelist-domain" cfg:"whitelist_domains" env:"OAUTH2_PROXY_WHITELIST_DOMAINS"`
	GitHubOrg                string   `flag:"github-org" cfg:"github_org" env:"OAUTH2_PROXY_GITHUB_ORG"`
	GitHubTeam               string   `flag:"github-team" cfg:"github_team" env:"OAUTH2_PROXY_GITHUB_TEAM"`
	GitHubRepo               string   `flag:"github-repo" cfg:"github_repo" env:"OAUTH2_PROXY_GITHUB_REPO"`
	GitHubToken              string   `flag:"github-token" cfg:"github_token" env:"OAUTH2_PROXY_GITHUB_TOKEN"`
	GitLabGroup              string   `flag:"gitlab-group" cfg:"gitlab_group" env:"OAUTH2_PROXY_GITLAB_GROUP"`
	GoogleGroups             []string `flag:"google-group" cfg:"google_group" env:"OAUTH2_PROXY_GOOGLE_GROUPS"`
	GoogleAdminEmail         string   `flag:"google-admin-email" cfg:"google_admin_email" env:"OAUTH2_PROXY_GOOGLE_ADMIN_EMAIL"`
	GoogleServiceAccountJSON string   `flag:"google-service-account-json" cfg:"google_service_account_json" env:"OAUTH2_PROXY_GOOGLE_SERVICE_ACCOUNT_JSON"`
	HtpasswdFile             string   `flag:"htpasswd-file" cfg:"htpasswd_file" env:"OAUTH2_PROXY_HTPASSWD_FILE"`
	DisplayHtpasswdForm      bool     `flag:"display-htpasswd-form" cfg:"display_htpasswd_form" env:"OAUTH2_PROXY_DISPLAY_HTPASSWD_FORM"`
	CustomTemplatesDir       string   `flag:"custom-templates-dir" cfg:"custom_templates_dir" env:"OAUTH2_PROXY_CUSTOM_TEMPLATES_DIR"`
	Banner                   string   `flag:"banner" cfg:"banner" env:"OAUTH2_PROXY_BANNER"`
	Footer                   string   `flag:"footer" cfg:"footer" env:"OAUTH2_PROXY_FOOTER"`

	Cookie  CookieOptions  `cfg:",squash"`
	Session SessionOptions `cfg:",squash"`

	Upstreams                     []string      `flag:"upstream" cfg:"upstreams" env:"OAUTH2_PROXY_UPSTREAMS"`
	SkipAuthRegex                 []string      `flag:"skip-auth-regex" cfg:"skip_auth_regex" env:"OAUTH2_PROXY_SKIP_AUTH_REGEX"`
	SkipJwtBearerTokens           bool          `flag:"skip-jwt-bearer-tokens" cfg:"skip_jwt_bearer_tokens" env:"OAUTH2_PROXY_SKIP_JWT_BEARER_TOKENS"`
	ExtraJwtIssuers               []string      `flag:"extra-jwt-issuers" cfg:"extra_jwt_issuers" env:"OAUTH2_PROXY_EXTRA_JWT_ISSUERS"`
	PassBasicAuth                 bool          `flag:"pass-basic-auth" cfg:"pass_basic_auth" env:"OAUTH2_PROXY_PASS_BASIC_AUTH"`
	SetBasicAuth                  bool          `flag:"set-basic-auth" cfg:"set_basic_auth" env:"OAUTH2_PROXY_SET_BASIC_AUTH"`
	PreferEmailToUser             bool          `flag:"prefer-email-to-user" cfg:"prefer_email_to_user" env:"OAUTH2_PROXY_PREFER_EMAIL_TO_USER"`
	BasicAuthPassword             string        `flag:"basic-auth-password" cfg:"basic_auth_password" env:"OAUTH2_PROXY_BASIC_AUTH_PASSWORD"`
	PassAccessToken               bool          `flag:"pass-access-token" cfg:"pass_access_token" env:"OAUTH2_PROXY_PASS_ACCESS_TOKEN"`
	PassHostHeader                bool          `flag:"pass-host-header" cfg:"pass_host_header" env:"OAUTH2_PROXY_PASS_HOST_HEADER"`
	SkipProviderButton            bool          `flag:"skip-provider-button" cfg:"skip_provider_button" env:"OAUTH2_PROXY_SKIP_PROVIDER_BUTTON"`
	PassUserHeaders               bool          `flag:"pass-user-headers" cfg:"pass_user_headers" env:"OAUTH2_PROXY_PASS_USER_HEADERS"`
	SSLInsecureSkipVerify         bool          `flag:"ssl-insecure-skip-verify" cfg:"ssl_insecure_skip_verify" env:"OAUTH2_PROXY_SSL_INSECURE_SKIP_VERIFY"`
	SSLUpstreamInsecureSkipVerify bool          `flag:"ssl-upstream-insecure-skip-verify" cfg:"ssl_upstream_insecure_skip_verify" env:"OAUTH2_PROXY_SSL_UPSTREAM_INSECURE_SKIP_VERIFY"`
	SetXAuthRequest               bool          `flag:"set-xauthrequest" cfg:"set_xauthrequest" env:"OAUTH2_PROXY_SET_XAUTHREQUEST"`
	SetAuthorization              bool          `flag:"set-authorization-header" cfg:"set_authorization_header" env:"OAUTH2_PROXY_SET_AUTHORIZATION_HEADER"`
	PassAuthorization             bool          `flag:"pass-authorization-header" cfg:"pass_authorization_header" env:"OAUTH2_PROXY_PASS_AUTHORIZATION_HEADER"`
	SkipAuthPreflight             bool          `flag:"skip-auth-preflight" cfg:"skip_auth_preflight" env:"OAUTH2_PROXY_SKIP_AUTH_PREFLIGHT"`
	FlushInterval                 time.Duration `flag:"flush-interval" cfg:"flush_interval" env:"OAUTH2_PROXY_FLUSH_INTERVAL"`

	// These options allow for other providers besides Google, with
	// potential overrides.
	ProviderType                       string `flag:"provider" cfg:"provider" env:"OAUTH2_PROXY_PROVIDER"`
	ProviderName                       string `flag:"provider-display-name" cfg:"provider_display_name" env:"OAUTH2_PROXY_PROVIDER_DISPLAY_NAME"`
	OIDCIssuerURL                      string `flag:"oidc-issuer-url" cfg:"oidc_issuer_url" env:"OAUTH2_PROXY_OIDC_ISSUER_URL"`
	InsecureOIDCAllowUnverifiedEmail   bool   `flag:"insecure-oidc-allow-unverified-email" cfg:"insecure_oidc_allow_unverified_email" env:"OAUTH2_PROXY_INSECURE_OIDC_ALLOW_UNVERIFIED_EMAIL"`
	InsecureOIDCSkipIssuerVerification bool   `flag:"insecure-oidc-skip-issuer-verification" cfg:"insecure_oidc_skip_issuer_verification" env:"OAUTH2_PROXY_INSECURE_OIDC_SKIP_ISSUER_VERIFICATION"`
	SkipOIDCDiscovery                  bool   `flag:"skip-oidc-discovery" cfg:"skip_oidc_discovery" env:"OAUTH2_PROXY_SKIP_OIDC_DISCOVERY"`
	OIDCJwksURL                        string `flag:"oidc-jwks-url" cfg:"oidc_jwks_url" env:"OAUTH2_PROXY_OIDC_JWKS_URL"`
	LoginURL                           string `flag:"login-url" cfg:"login_url" env:"OAUTH2_PROXY_LOGIN_URL"`
	RedeemURL                          string `flag:"redeem-url" cfg:"redeem_url" env:"OAUTH2_PROXY_REDEEM_URL"`
	ProfileURL                         string `flag:"profile-url" cfg:"profile_url" env:"OAUTH2_PROXY_PROFILE_URL"`
	ProtectedResource                  string `flag:"resource" cfg:"resource" env:"OAUTH2_PROXY_RESOURCE"`
	ValidateURL                        string `flag:"validate-url" cfg:"validate_url" env:"OAUTH2_PROXY_VALIDATE_URL"`
	Scope                              string `flag:"scope" cfg:"scope" env:"OAUTH2_PROXY_SCOPE"`
	Prompt                             string `flag:"prompt" cfg:"prompt" env:"OAUTH2_PROXY_PROMPT"`
	ApprovalPrompt                     string `flag:"approval-prompt" cfg:"approval_prompt" env:"OAUTH2_PROXY_APPROVAL_PROMPT"` // Deprecated by OIDC 1.0
	UserIDClaim                        string `flag:"user-id-claim" cfg:"user_id_claim" env:"OAUTH2_PROXY_USER_ID_CLAIM"`

	// Configuration values for logging
	LoggingFilename       string `flag:"logging-filename" cfg:"logging_filename" env:"OAUTH2_PROXY_LOGGING_FILENAME"`
	LoggingMaxSize        int    `flag:"logging-max-size" cfg:"logging_max_size" env:"OAUTH2_PROXY_LOGGING_MAX_SIZE"`
	LoggingMaxAge         int    `flag:"logging-max-age" cfg:"logging_max_age" env:"OAUTH2_PROXY_LOGGING_MAX_AGE"`
	LoggingMaxBackups     int    `flag:"logging-max-backups" cfg:"logging_max_backups" env:"OAUTH2_PROXY_LOGGING_MAX_BACKUPS"`
	LoggingLocalTime      bool   `flag:"logging-local-time" cfg:"logging_local_time" env:"OAUTH2_PROXY_LOGGING_LOCAL_TIME"`
	LoggingCompress       bool   `flag:"logging-compress" cfg:"logging_compress" env:"OAUTH2_PROXY_LOGGING_COMPRESS"`
	StandardLogging       bool   `flag:"standard-logging" cfg:"standard_logging" env:"OAUTH2_PROXY_STANDARD_LOGGING"`
	StandardLoggingFormat string `flag:"standard-logging-format" cfg:"standard_logging_format" env:"OAUTH2_PROXY_STANDARD_LOGGING_FORMAT"`
	RequestLogging        bool   `flag:"request-logging" cfg:"request_logging" env:"OAUTH2_PROXY_REQUEST_LOGGING"`
	RequestLoggingFormat  string `flag:"request-logging-format" cfg:"request_logging_format" env:"OAUTH2_PROXY_REQUEST_LOGGING_FORMAT"`
	ExcludeLoggingPaths   string `flag:"exclude-logging-paths" cfg:"exclude_logging_paths" env:"OAUTH2_PROXY_EXCLUDE_LOGGING_PATHS"`
	SilencePingLogging    bool   `flag:"silence-ping-logging" cfg:"silence_ping_logging" env:"OAUTH2_PROXY_SILENCE_PING_LOGGING"`
	AuthLogging           bool   `flag:"auth-logging" cfg:"auth_logging" env:"OAUTH2_PROXY_LOGGING_AUTH_LOGGING"`
	AuthLoggingFormat     string `flag:"auth-logging-format" cfg:"auth_logging_format" env:"OAUTH2_PROXY_AUTH_LOGGING_FORMAT"`
	SignatureKey          string `flag:"signature-key" cfg:"signature_key" env:"OAUTH2_PROXY_SIGNATURE_KEY"`
	AcrValues             string `flag:"acr-values" cfg:"acr_values" env:"OAUTH2_PROXY_ACR_VALUES"`
	JWTKey                string `flag:"jwt-key" cfg:"jwt_key" env:"OAUTH2_PROXY_JWT_KEY"`
	JWTKeyFile            string `flag:"jwt-key-file" cfg:"jwt_key_file" env:"OAUTH2_PROXY_JWT_KEY_FILE"`
	PubJWKURL             string `flag:"pubjwk-url" cfg:"pubjwk_url" env:"OAUTH2_PROXY_PUBJWK_URL"`
	GCPHealthChecks       bool   `flag:"gcp-healthchecks" cfg:"gcp_healthchecks" env:"OAUTH2_PROXY_GCP_HEALTHCHECKS"`

	// internal values that are set after config validation
	redirectURL        *url.URL
	proxyURLs          []*url.URL
	compiledRegex      []*regexp.Regexp
	provider           providers.Provider
	sessionStore       sessionsapi.SessionStore
	signatureData      *SignatureData
	oidcVerifier       *oidc.IDTokenVerifier
	jwtBearerVerifiers []*oidc.IDTokenVerifier
	realClientIPParser logging.RealClientIPParser
}

// Options for Getting internal values
func (o *Options) GetRedirectURL() *url.URL                          { return o.redirectURL }
func (o *Options) GetProxyURLs() []*url.URL                          { return o.proxyURLs }
func (o *Options) GetCompiledRegex() []*regexp.Regexp                { return o.compiledRegex }
func (o *Options) GetProvider() providers.Provider                   { return o.provider }
func (o *Options) GetSessionStore() sessionsapi.SessionStore         { return o.sessionStore }
func (o *Options) GetSignatureData() *SignatureData                  { return o.signatureData }
func (o *Options) GetOIDCVerifier() *oidc.IDTokenVerifier            { return o.oidcVerifier }
func (o *Options) GetJWTBearerVerifiers() []*oidc.IDTokenVerifier    { return o.jwtBearerVerifiers }
func (o *Options) GetRealClientIPParser() logging.RealClientIPParser { return o.realClientIPParser }

// Options for Setting internal values
func (o *Options) SetRedirectURL(s *url.URL)                          { o.redirectURL = s }
func (o *Options) SetProxyURLs(s []*url.URL)                          { o.proxyURLs = s }
func (o *Options) SetCompiledRegex(s []*regexp.Regexp)                { o.compiledRegex = s }
func (o *Options) SetProvider(s providers.Provider)                   { o.provider = s }
func (o *Options) SetSessionStore(s sessionsapi.SessionStore)         { o.sessionStore = s }
func (o *Options) SetSignatureData(s *SignatureData)                  { o.signatureData = s }
func (o *Options) SetOIDCVerifier(s *oidc.IDTokenVerifier)            { o.oidcVerifier = s }
func (o *Options) SetJWTBearerVerifiers(s []*oidc.IDTokenVerifier)    { o.jwtBearerVerifiers = s }
func (o *Options) SetRealClientIPParser(s logging.RealClientIPParser) { o.realClientIPParser = s }

// NewOptions constructs a new Options with defaulted values
func NewOptions() *Options {
	return &Options{
		ProxyPrefix:         "/oauth2",
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
		},
		Session: SessionOptions{
			Type: "cookie",
		},
		SetXAuthRequest:                  false,
		SkipAuthPreflight:                false,
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
		LoggingFilename:                  "",
		LoggingMaxSize:                   100,
		LoggingMaxAge:                    7,
		LoggingMaxBackups:                0,
		LoggingLocalTime:                 true,
		LoggingCompress:                  false,
		ExcludeLoggingPaths:              "",
		SilencePingLogging:               false,
		StandardLogging:                  true,
		StandardLoggingFormat:            logger.DefaultStandardLoggingFormat,
		RequestLogging:                   true,
		RequestLoggingFormat:             logger.DefaultRequestLoggingFormat,
		AuthLogging:                      true,
		AuthLoggingFormat:                logger.DefaultAuthLoggingFormat,
	}
}
