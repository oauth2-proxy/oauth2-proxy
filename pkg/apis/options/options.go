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

	// Configuration values for logging
	LoggingFilename       string `flag:"logging-filename" cfg:"logging_filename"`
	LoggingMaxSize        int    `flag:"logging-max-size" cfg:"logging_max_size"`
	LoggingMaxAge         int    `flag:"logging-max-age" cfg:"logging_max_age"`
	LoggingMaxBackups     int    `flag:"logging-max-backups" cfg:"logging_max_backups"`
	LoggingLocalTime      bool   `flag:"logging-local-time" cfg:"logging_local_time"`
	LoggingCompress       bool   `flag:"logging-compress" cfg:"logging_compress"`
	StandardLogging       bool   `flag:"standard-logging" cfg:"standard_logging"`
	StandardLoggingFormat string `flag:"standard-logging-format" cfg:"standard_logging_format"`
	RequestLogging        bool   `flag:"request-logging" cfg:"request_logging"`
	RequestLoggingFormat  string `flag:"request-logging-format" cfg:"request_logging_format"`
	ExcludeLoggingPaths   string `flag:"exclude-logging-paths" cfg:"exclude_logging_paths"`
	SilencePingLogging    bool   `flag:"silence-ping-logging" cfg:"silence_ping_logging"`
	AuthLogging           bool   `flag:"auth-logging" cfg:"auth_logging"`
	AuthLoggingFormat     string `flag:"auth-logging-format" cfg:"auth_logging_format"`
	SignatureKey          string `flag:"signature-key" cfg:"signature_key"`
	AcrValues             string `flag:"acr-values" cfg:"acr_values"`
	JWTKey                string `flag:"jwt-key" cfg:"jwt_key"`
	JWTKeyFile            string `flag:"jwt-key-file" cfg:"jwt_key_file"`
	PubJWKURL             string `flag:"pubjwk-url" cfg:"pubjwk_url"`
	GCPHealthChecks       bool   `flag:"gcp-healthchecks" cfg:"gcp_healthchecks"`

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
