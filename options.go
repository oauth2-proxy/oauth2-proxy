package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc"
	"github.com/dgrijalva/jwt-go"
	"github.com/mbland/hmacauth"
	"github.com/pusher/oauth2_proxy/logger"
	"github.com/pusher/oauth2_proxy/providers"
	"gopkg.in/natefinch/lumberjack.v2"
)

// Options holds Configuration Options that can be set by Command Line Flag,
// or Config File
type Options struct {
	ProxyPrefix     string `flag:"proxy-prefix" cfg:"proxy-prefix" env:"OAUTH2_PROXY_PROXY_PREFIX"`
	ProxyWebSockets bool   `flag:"proxy-websockets" cfg:"proxy_websockets" env:"OAUTH2_PROXY_PROXY_WEBSOCKETS"`
	HTTPAddress     string `flag:"http-address" cfg:"http_address" env:"OAUTH2_PROXY_HTTP_ADDRESS"`
	HTTPSAddress    string `flag:"https-address" cfg:"https_address" env:"OAUTH2_PROXY_HTTPS_ADDRESS"`
	RedirectURL     string `flag:"redirect-url" cfg:"redirect_url" env:"OAUTH2_PROXY_REDIRECT_URL"`
	ClientID        string `flag:"client-id" cfg:"client_id" env:"OAUTH2_PROXY_CLIENT_ID"`
	ClientSecret    string `flag:"client-secret" cfg:"client_secret" env:"OAUTH2_PROXY_CLIENT_SECRET"`
	TLSCertFile     string `flag:"tls-cert" cfg:"tls_cert_file" env:"OAUTH2_PROXY_TLS_CERT_FILE"`
	TLSKeyFile      string `flag:"tls-key" cfg:"tls_key_file" env:"OAUTH2_PROXY_TLS_KEY_FILE"`

	AuthenticatedEmailsFile  string   `flag:"authenticated-emails-file" cfg:"authenticated_emails_file" env:"OAUTH2_PROXY_AUTHENTICATED_EMAILS_FILE"`
	AzureTenant              string   `flag:"azure-tenant" cfg:"azure_tenant" env:"OAUTH2_PROXY_AZURE_TENANT"`
	EmailDomains             []string `flag:"email-domain" cfg:"email_domains" env:"OAUTH2_PROXY_EMAIL_DOMAINS"`
	WhitelistDomains         []string `flag:"whitelist-domain" cfg:"whitelist_domains" env:"OAUTH2_PROXY_WHITELIST_DOMAINS"`
	GitHubOrg                string   `flag:"github-org" cfg:"github_org" env:"OAUTH2_PROXY_GITHUB_ORG"`
	GitHubTeam               string   `flag:"github-team" cfg:"github_team" env:"OAUTH2_PROXY_GITHUB_TEAM"`
	GoogleGroups             []string `flag:"google-group" cfg:"google_group" env:"OAUTH2_PROXY_GOOGLE_GROUPS"`
	GoogleAdminEmail         string   `flag:"google-admin-email" cfg:"google_admin_email" env:"OAUTH2_PROXY_GOOGLE_ADMIN_EMAIL"`
	GoogleServiceAccountJSON string   `flag:"google-service-account-json" cfg:"google_service_account_json" env:"OAUTH2_PROXY_GOOGLE_SERVICE_ACCOUNT_JSON"`
	HtpasswdFile             string   `flag:"htpasswd-file" cfg:"htpasswd_file" env:"OAUTH2_PROXY_HTPASSWD_FILE"`
	DisplayHtpasswdForm      bool     `flag:"display-htpasswd-form" cfg:"display_htpasswd_form" env:"OAUTH2_PROXY_DISPLAY_HTPASSWD_FORM"`
	CustomTemplatesDir       string   `flag:"custom-templates-dir" cfg:"custom_templates_dir" env:"OAUTH2_PROXY_CUSTOM_TEMPLATES_DIR"`
	Footer                   string   `flag:"footer" cfg:"footer" env:"OAUTH2_PROXY_FOOTER"`

	CookieName     string        `flag:"cookie-name" cfg:"cookie_name" env:"OAUTH2_PROXY_COOKIE_NAME"`
	CookieSecret   string        `flag:"cookie-secret" cfg:"cookie_secret" env:"OAUTH2_PROXY_COOKIE_SECRET"`
	CookieDomain   string        `flag:"cookie-domain" cfg:"cookie_domain" env:"OAUTH2_PROXY_COOKIE_DOMAIN"`
	CookiePath     string        `flag:"cookie-path" cfg:"cookie_path" env:"OAUTH2_PROXY_COOKIE_PATH"`
	CookieExpire   time.Duration `flag:"cookie-expire" cfg:"cookie_expire" env:"OAUTH2_PROXY_COOKIE_EXPIRE"`
	CookieRefresh  time.Duration `flag:"cookie-refresh" cfg:"cookie_refresh" env:"OAUTH2_PROXY_COOKIE_REFRESH"`
	CookieSecure   bool          `flag:"cookie-secure" cfg:"cookie_secure" env:"OAUTH2_PROXY_COOKIE_SECURE"`
	CookieHTTPOnly bool          `flag:"cookie-httponly" cfg:"cookie_httponly" env:"OAUTH2_PROXY_COOKIE_HTTPONLY"`

	Upstreams             []string      `flag:"upstream" cfg:"upstreams" env:"OAUTH2_PROXY_UPSTREAMS"`
	SkipAuthRegex         []string      `flag:"skip-auth-regex" cfg:"skip_auth_regex" env:"OAUTH2_PROXY_SKIP_AUTH_REGEX"`
	PassBasicAuth         bool          `flag:"pass-basic-auth" cfg:"pass_basic_auth" env:"OAUTH2_PROXY_PASS_BASIC_AUTH"`
	BasicAuthPassword     string        `flag:"basic-auth-password" cfg:"basic_auth_password" env:"OAUTH2_PROXY_BASIC_AUTH_PASSWORD"`
	PassAccessToken       bool          `flag:"pass-access-token" cfg:"pass_access_token" env:"OAUTH2_PROXY_PASS_ACCESS_TOKEN"`
	PassHostHeader        bool          `flag:"pass-host-header" cfg:"pass_host_header" env:"OAUTH2_PROXY_PASS_HOST_HEADER"`
	SkipProviderButton    bool          `flag:"skip-provider-button" cfg:"skip_provider_button" env:"OAUTH2_PROXY_SKIP_PROVIDER_BUTTON"`
	PassUserHeaders       bool          `flag:"pass-user-headers" cfg:"pass_user_headers" env:"OAUTH2_PROXY_PASS_USER_HEADERS"`
	SSLInsecureSkipVerify bool          `flag:"ssl-insecure-skip-verify" cfg:"ssl_insecure_skip_verify" env:"OAUTH2_PROXY_SSL_INSECURE_SKIP_VERIFY"`
	SetXAuthRequest       bool          `flag:"set-xauthrequest" cfg:"set_xauthrequest" env:"OAUTH2_PROXY_SET_XAUTHREQUEST"`
	SetAuthorization      bool          `flag:"set-authorization-header" cfg:"set_authorization_header" env:"OAUTH2_PROXY_SET_AUTHORIZATION_HEADER"`
	PassAuthorization     bool          `flag:"pass-authorization-header" cfg:"pass_authorization_header" env:"OAUTH2_PROXY_PASS_AUTHORIZATION_HEADER"`
	SkipAuthPreflight     bool          `flag:"skip-auth-preflight" cfg:"skip_auth_preflight" env:"OAUTH2_PROXY_SKIP_AUTH_PREFLIGHT"`
	FlushInterval         time.Duration `flag:"flush-interval" cfg:"flush_interval" env:"OAUTH2_PROXY_FLUSH_INTERVAL"`

	// These options allow for other providers besides Google, with
	// potential overrides.
	Provider          string `flag:"provider" cfg:"provider" env:"OAUTH2_PROXY_PROVIDER"`
	OIDCIssuerURL     string `flag:"oidc-issuer-url" cfg:"oidc_issuer_url" env:"OAUTH2_PROXY_OIDC_ISSUER_URL"`
	SkipOIDCDiscovery bool   `flag:"skip-oidc-discovery" cfg:"skip_oidc_discovery" env:"OAUTH2_SKIP_OIDC_DISCOVERY"`
	OIDCJwksURL       string `flag:"oidc-jwks-url" cfg:"oidc_jwks_url" env:"OAUTH2_OIDC_JWKS_URL"`
	LoginURL          string `flag:"login-url" cfg:"login_url" env:"OAUTH2_PROXY_LOGIN_URL"`
	RedeemURL         string `flag:"redeem-url" cfg:"redeem_url" env:"OAUTH2_PROXY_REDEEM_URL"`
	ProfileURL        string `flag:"profile-url" cfg:"profile_url" env:"OAUTH2_PROXY_PROFILE_URL"`
	ProtectedResource string `flag:"resource" cfg:"resource" env:"OAUTH2_PROXY_RESOURCE"`
	ValidateURL       string `flag:"validate-url" cfg:"validate_url" env:"OAUTH2_PROXY_VALIDATE_URL"`
	Scope             string `flag:"scope" cfg:"scope" env:"OAUTH2_PROXY_SCOPE"`
	ApprovalPrompt    string `flag:"approval-prompt" cfg:"approval_prompt" env:"OAUTH2_PROXY_APPROVAL_PROMPT"`

	// Configuration values for logging
	LoggingFilename       string `flag:"logging-filename" cfg:"logging_filename" env:"OAUTH2_LOGGING_FILENAME"`
	LoggingMaxSize        int    `flag:"logging-max-size" cfg:"logging_max_size" env:"OAUTH2_LOGGING_MAX_SIZE"`
	LoggingMaxAge         int    `flag:"logging-max-age" cfg:"logging_max_age" env:"OAUTH2_LOGGING_MAX_AGE"`
	LoggingMaxBackups     int    `flag:"logging-max-backups" cfg:"logging_max_backups" env:"OAUTH2_LOGGING_MAX_BACKUPS"`
	LoggingLocalTime      bool   `flag:"logging-local-time" cfg:"logging_local_time" env:"OAUTH2_LOGGING_LOCAL_TIME"`
	LoggingCompress       bool   `flag:"logging-compress" cfg:"logging_compress" env:"OAUTH2_LOGGING_COMPRESS"`
	StandardLogging       bool   `flag:"standard-logging" cfg:"standard_logging" env:"OAUTH2_STANDARD_LOGGING"`
	StandardLoggingFormat string `flag:"standard-logging-format" cfg:"standard_logging_format" env:"OAUTH2_STANDARD_LOGGING_FORMAT"`
	RequestLogging        bool   `flag:"request-logging" cfg:"request_logging" env:"OAUTH2_REQUEST_LOGGING"`
	RequestLoggingFormat  string `flag:"request-logging-format" cfg:"request_logging_format" env:"OAUTH2_REQUEST_LOGGING_FORMAT"`
	AuthLogging           bool   `flag:"auth-logging" cfg:"auth_logging" env:"OAUTH2_LOGGING_AUTH_LOGGING"`
	AuthLoggingFormat     string `flag:"auth-logging-format" cfg:"auth_logging_format" env:"OAUTH2_AUTH_LOGGING_FORMAT"`

	SignatureKey    string `flag:"signature-key" cfg:"signature_key" env:"OAUTH2_PROXY_SIGNATURE_KEY"`
	AcrValues       string `flag:"acr-values" cfg:"acr_values" env:"OAUTH2_PROXY_ACR_VALUES"`
	JWTKey          string `flag:"jwt-key" cfg:"jwt_key" env:"OAUTH2_PROXY_JWT_KEY"`
	JWTKeyFile      string `flag:"jwt-key-file" cfg:"jwt_key_file" env:"OAUTH2_PROXY_JWT_KEY_FILE"`
	PubJWKURL       string `flag:"pubjwk-url" cfg:"pubjwk_url" env:"OAUTH2_PROXY_PUBJWK_URL"`
	GCPHealthChecks bool   `flag:"gcp-healthchecks" cfg:"gcp_healthchecks" env:"OAUTH2_PROXY_GCP_HEALTHCHECKS"`

	// internal values that are set after config validation
	redirectURL   *url.URL
	proxyURLs     []*url.URL
	CompiledRegex []*regexp.Regexp
	provider      providers.Provider
	signatureData *SignatureData
	oidcVerifier  *oidc.IDTokenVerifier
}

// SignatureData holds hmacauth signature hash and key
type SignatureData struct {
	hash crypto.Hash
	key  string
}

// NewOptions constructs a new Options with defaulted values
func NewOptions() *Options {
	return &Options{
		ProxyPrefix:           "/oauth2",
		ProxyWebSockets:       true,
		HTTPAddress:           "127.0.0.1:4180",
		HTTPSAddress:          ":443",
		DisplayHtpasswdForm:   true,
		CookieName:            "_oauth2_proxy",
		CookieSecure:          true,
		CookieHTTPOnly:        true,
		CookieExpire:          time.Duration(168) * time.Hour,
		CookieRefresh:         time.Duration(0),
		SetXAuthRequest:       false,
		SkipAuthPreflight:     false,
		PassBasicAuth:         true,
		PassUserHeaders:       true,
		PassAccessToken:       false,
		PassHostHeader:        true,
		SetAuthorization:      false,
		PassAuthorization:     false,
		ApprovalPrompt:        "force",
		SkipOIDCDiscovery:     false,
		LoggingFilename:       "",
		LoggingMaxSize:        100,
		LoggingMaxAge:         7,
		LoggingMaxBackups:     0,
		LoggingLocalTime:      true,
		LoggingCompress:       false,
		StandardLogging:       true,
		StandardLoggingFormat: logger.DefaultStandardLoggingFormat,
		RequestLogging:        true,
		RequestLoggingFormat:  logger.DefaultRequestLoggingFormat,
		AuthLogging:           true,
		AuthLoggingFormat:     logger.DefaultAuthLoggingFormat,
	}
}

func parseURL(toParse string, urltype string, msgs []string) (*url.URL, []string) {
	parsed, err := url.Parse(toParse)
	if err != nil {
		return nil, append(msgs, fmt.Sprintf(
			"error parsing %s-url=%q %s", urltype, toParse, err))
	}
	return parsed, msgs
}

// Validate checks that required options are set and validates those that they
// are of the correct format
func (o *Options) Validate() error {
	if o.SSLInsecureSkipVerify {
		// TODO: Accept a certificate bundle.
		insecureTransport := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		http.DefaultClient = &http.Client{Transport: insecureTransport}
	}

	msgs := make([]string, 0)
	if o.CookieSecret == "" {
		msgs = append(msgs, "missing setting: cookie-secret")
	}
	if o.ClientID == "" {
		msgs = append(msgs, "missing setting: client-id")
	}
	// login.gov uses a signed JWT to authenticate, not a client-secret
	if o.ClientSecret == "" && o.Provider != "login.gov" {
		msgs = append(msgs, "missing setting: client-secret")
	}
	if o.AuthenticatedEmailsFile == "" && len(o.EmailDomains) == 0 && o.HtpasswdFile == "" {
		msgs = append(msgs, "missing setting for email validation: email-domain or authenticated-emails-file required."+
			"\n      use email-domain=* to authorize all email addresses")
	}

	if o.OIDCIssuerURL != "" {

		ctx := context.Background()

		// Construct a manual IDTokenVerifier from issuer URL & JWKS URI
		// instead of metadata discovery if we enable -skip-oidc-discovery.
		// In this case we need to make sure the required endpoints for
		// the provider are configured.
		if o.SkipOIDCDiscovery {
			if o.LoginURL == "" {
				msgs = append(msgs, "missing setting: login-url")
			}
			if o.RedeemURL == "" {
				msgs = append(msgs, "missing setting: redeem-url")
			}
			if o.OIDCJwksURL == "" {
				msgs = append(msgs, "missing setting: oidc-jwks-url")
			}
			keySet := oidc.NewRemoteKeySet(ctx, o.OIDCJwksURL)
			o.oidcVerifier = oidc.NewVerifier(o.OIDCIssuerURL, keySet, &oidc.Config{
				ClientID: o.ClientID,
			})
		} else {
			// Configure discoverable provider data.
			provider, err := oidc.NewProvider(ctx, o.OIDCIssuerURL)
			if err != nil {
				return err
			}
			o.oidcVerifier = provider.Verifier(&oidc.Config{
				ClientID: o.ClientID,
			})

			o.LoginURL = provider.Endpoint().AuthURL
			o.RedeemURL = provider.Endpoint().TokenURL
		}
		if o.Scope == "" {
			o.Scope = "openid email profile"
		}
	}

	o.redirectURL, msgs = parseURL(o.RedirectURL, "redirect", msgs)

	for _, u := range o.Upstreams {
		upstreamURL, err := url.Parse(u)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("error parsing upstream: %s", err))
		} else {
			if upstreamURL.Path == "" {
				upstreamURL.Path = "/"
			}
			o.proxyURLs = append(o.proxyURLs, upstreamURL)
		}
	}

	for _, u := range o.SkipAuthRegex {
		CompiledRegex, err := regexp.Compile(u)
		if err != nil {
			msgs = append(msgs, fmt.Sprintf("error compiling regex=%q %s", u, err))
			continue
		}
		o.CompiledRegex = append(o.CompiledRegex, CompiledRegex)
	}
	msgs = parseProviderInfo(o, msgs)

	if o.PassAccessToken || (o.CookieRefresh != time.Duration(0)) {
		validCookieSecretSize := false
		for _, i := range []int{16, 24, 32} {
			if len(secretBytes(o.CookieSecret)) == i {
				validCookieSecretSize = true
			}
		}
		var decoded bool
		if string(secretBytes(o.CookieSecret)) != o.CookieSecret {
			decoded = true
		}
		if validCookieSecretSize == false {
			var suffix string
			if decoded {
				suffix = fmt.Sprintf(" note: cookie secret was base64 decoded from %q", o.CookieSecret)
			}
			msgs = append(msgs, fmt.Sprintf(
				"cookie_secret must be 16, 24, or 32 bytes "+
					"to create an AES cipher when "+
					"pass_access_token == true or "+
					"cookie_refresh != 0, but is %d bytes.%s",
				len(secretBytes(o.CookieSecret)), suffix))
		}
	}

	if o.CookieRefresh >= o.CookieExpire {
		msgs = append(msgs, fmt.Sprintf(
			"cookie_refresh (%s) must be less than "+
				"cookie_expire (%s)",
			o.CookieRefresh.String(),
			o.CookieExpire.String()))
	}

	if len(o.GoogleGroups) > 0 || o.GoogleAdminEmail != "" || o.GoogleServiceAccountJSON != "" {
		if len(o.GoogleGroups) < 1 {
			msgs = append(msgs, "missing setting: google-group")
		}
		if o.GoogleAdminEmail == "" {
			msgs = append(msgs, "missing setting: google-admin-email")
		}
		if o.GoogleServiceAccountJSON == "" {
			msgs = append(msgs, "missing setting: google-service-account-json")
		}
	}

	msgs = parseSignatureKey(o, msgs)
	msgs = validateCookieName(o, msgs)
	msgs = setupLogger(o, msgs)

	if len(msgs) != 0 {
		return fmt.Errorf("Invalid configuration:\n  %s",
			strings.Join(msgs, "\n  "))
	}
	return nil
}

func parseProviderInfo(o *Options, msgs []string) []string {
	p := &providers.ProviderData{
		Scope:          o.Scope,
		ClientID:       o.ClientID,
		ClientSecret:   o.ClientSecret,
		ApprovalPrompt: o.ApprovalPrompt,
	}
	p.LoginURL, msgs = parseURL(o.LoginURL, "login", msgs)
	p.RedeemURL, msgs = parseURL(o.RedeemURL, "redeem", msgs)
	p.ProfileURL, msgs = parseURL(o.ProfileURL, "profile", msgs)
	p.ValidateURL, msgs = parseURL(o.ValidateURL, "validate", msgs)
	p.ProtectedResource, msgs = parseURL(o.ProtectedResource, "resource", msgs)

	o.provider = providers.New(o.Provider, p)
	switch p := o.provider.(type) {
	case *providers.AzureProvider:
		p.Configure(o.AzureTenant)
	case *providers.GitHubProvider:
		p.SetOrgTeam(o.GitHubOrg, o.GitHubTeam)
	case *providers.GoogleProvider:
		if o.GoogleServiceAccountJSON != "" {
			file, err := os.Open(o.GoogleServiceAccountJSON)
			if err != nil {
				msgs = append(msgs, "invalid Google credentials file: "+o.GoogleServiceAccountJSON)
			} else {
				p.SetGroupRestriction(o.GoogleGroups, o.GoogleAdminEmail, file)
			}
		}
	case *providers.OIDCProvider:
		if o.oidcVerifier == nil {
			msgs = append(msgs, "oidc provider requires an oidc issuer URL")
		} else {
			p.Verifier = o.oidcVerifier
		}
	case *providers.LoginGovProvider:
		p.AcrValues = o.AcrValues
		p.PubJWKURL, msgs = parseURL(o.PubJWKURL, "pubjwk", msgs)

		// JWT key can be supplied via env variable or file in the filesystem, but not both.
		switch {
		case o.JWTKey != "" && o.JWTKeyFile != "":
			msgs = append(msgs, "cannot set both jwt-key and jwt-key-file options")
		case o.JWTKey == "" && o.JWTKeyFile == "":
			msgs = append(msgs, "login.gov provider requires a private key for signing JWTs")
		case o.JWTKey != "":
			// The JWT Key is in the commandline argument
			signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(o.JWTKey))
			if err != nil {
				msgs = append(msgs, "could not parse RSA Private Key PEM")
			} else {
				p.JWTKey = signKey
			}
		case o.JWTKeyFile != "":
			// The JWT key is in the filesystem
			keyData, err := ioutil.ReadFile(o.JWTKeyFile)
			if err != nil {
				msgs = append(msgs, "could not read key file: "+o.JWTKeyFile)
			}
			signKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
			if err != nil {
				msgs = append(msgs, "could not parse private key from PEM file:"+o.JWTKeyFile)
			} else {
				p.JWTKey = signKey
			}
		}
	}
	return msgs
}

func parseSignatureKey(o *Options, msgs []string) []string {
	if o.SignatureKey == "" {
		return msgs
	}

	components := strings.Split(o.SignatureKey, ":")
	if len(components) != 2 {
		return append(msgs, "invalid signature hash:key spec: "+
			o.SignatureKey)
	}

	algorithm, secretKey := components[0], components[1]
	var hash crypto.Hash
	var err error
	if hash, err = hmacauth.DigestNameToCryptoHash(algorithm); err != nil {
		return append(msgs, "unsupported signature hash algorithm: "+
			o.SignatureKey)
	}
	o.signatureData = &SignatureData{hash, secretKey}
	return msgs
}

func validateCookieName(o *Options, msgs []string) []string {
	cookie := &http.Cookie{Name: o.CookieName}
	if cookie.String() == "" {
		return append(msgs, fmt.Sprintf("invalid cookie name: %q", o.CookieName))
	}
	return msgs
}

func addPadding(secret string) string {
	padding := len(secret) % 4
	switch padding {
	case 1:
		return secret + "==="
	case 2:
		return secret + "=="
	case 3:
		return secret + "="
	default:
		return secret
	}
}

// secretBytes attempts to base64 decode the secret, if that fails it treats the secret as binary
func secretBytes(secret string) []byte {
	b, err := base64.URLEncoding.DecodeString(addPadding(secret))
	if err == nil {
		return []byte(addPadding(string(b)))
	}
	return []byte(secret)
}

func setupLogger(o *Options, msgs []string) []string {
	// Setup the log file
	if len(o.LoggingFilename) > 0 {
		// Validate that the file/dir can be written
		file, err := os.OpenFile(o.LoggingFilename, os.O_WRONLY|os.O_CREATE, 0666)
		if err != nil {
			if os.IsPermission(err) {
				return append(msgs, "unable to write to log file: "+o.LoggingFilename)
			}
		}
		file.Close()

		logger.Printf("Redirecting logging to file: %s", o.LoggingFilename)

		logWriter := &lumberjack.Logger{
			Filename:   o.LoggingFilename,
			MaxSize:    o.LoggingMaxSize, // megabytes
			MaxAge:     o.LoggingMaxAge,  // days
			MaxBackups: o.LoggingMaxBackups,
			LocalTime:  o.LoggingLocalTime,
			Compress:   o.LoggingCompress,
		}

		logger.SetOutput(logWriter)
	}

	// Supply a sanity warning to the logger if all logging is disabled
	if !o.StandardLogging && !o.AuthLogging && !o.RequestLogging {
		logger.Print("Warning: Logging disabled. No further logs will be shown.")
	}

	// Pass configuration values to the standard logger
	logger.SetStandardEnabled(o.StandardLogging)
	logger.SetAuthEnabled(o.AuthLogging)
	logger.SetReqEnabled(o.RequestLogging)
	logger.SetStandardTemplate(o.StandardLoggingFormat)
	logger.SetAuthTemplate(o.AuthLoggingFormat)
	logger.SetReqTemplate(o.RequestLoggingFormat)

	if !o.LoggingLocalTime {
		logger.SetFlags(logger.Flags() | logger.LUTC)
	}

	return msgs
}
