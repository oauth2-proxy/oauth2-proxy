package options

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/providers"
	"github.com/spf13/pflag"
)

type LegacyOptions struct {
	// Legacy options related to upstream servers
	LegacyUpstreams LegacyUpstreams `cfg:",squash"`

	// Legacy options for injecting request/response headers
	LegacyHeaders LegacyHeaders `cfg:",squash"`

	// Legacy options for the server address and TLS
	LegacyServer LegacyServer `cfg:",squash"`

	// Legacy options for single provider
	LegacyProvider LegacyProvider `cfg:",squash"`

	Options Options `cfg:",squash"`
}

func NewLegacyOptions() *LegacyOptions {
	return &LegacyOptions{
		LegacyUpstreams: LegacyUpstreams{
			PassHostHeader:  true,
			ProxyWebSockets: true,
			FlushInterval:   DefaultUpstreamFlushInterval,
		},

		LegacyHeaders: LegacyHeaders{
			PassBasicAuth:        true,
			PassUserHeaders:      true,
			SkipAuthStripHeaders: true,
		},

		LegacyServer: LegacyServer{
			HTTPAddress:  "127.0.0.1:4180",
			HTTPSAddress: ":443",
		},

		LegacyProvider: LegacyProvider{
			ProviderType:          "google",
			AzureTenant:           "common",
			ApprovalPrompt:        "force",
			UserIDClaim:           "email",
			OIDCEmailClaim:        "email",
			OIDCGroupsClaim:       "groups",
			InsecureOIDCSkipNonce: true,
		},

		Options: *NewOptions(),
	}
}

func NewLegacyFlagSet() *pflag.FlagSet {
	flagSet := NewFlagSet()

	flagSet.AddFlagSet(legacyUpstreamsFlagSet())
	flagSet.AddFlagSet(legacyHeadersFlagSet())
	flagSet.AddFlagSet(legacyServerFlagset())
	flagSet.AddFlagSet(legacyProviderFlagSet())

	return flagSet
}

func (l *LegacyOptions) ToOptions() (*Options, error) {
	upstreams, err := l.LegacyUpstreams.convert()
	if err != nil {
		return nil, fmt.Errorf("error converting upstreams: %v", err)
	}
	l.Options.UpstreamServers = upstreams

	l.Options.InjectRequestHeaders, l.Options.InjectResponseHeaders = l.LegacyHeaders.convert()

	l.Options.Server, l.Options.MetricsServer = l.LegacyServer.convert()

	l.Options.LegacyPreferEmailToUser = l.LegacyHeaders.PreferEmailToUser

	providers, err := l.LegacyProvider.convert()
	if err != nil {
		return nil, fmt.Errorf("error converting provider: %v", err)
	}
	l.Options.Providers = providers

	return &l.Options, nil
}

type LegacyUpstreams struct {
	FlushInterval                 time.Duration `flag:"flush-interval" cfg:"flush_interval"`
	PassHostHeader                bool          `flag:"pass-host-header" cfg:"pass_host_header"`
	ProxyWebSockets               bool          `flag:"proxy-websockets" cfg:"proxy_websockets"`
	SSLUpstreamInsecureSkipVerify bool          `flag:"ssl-upstream-insecure-skip-verify" cfg:"ssl_upstream_insecure_skip_verify"`
	Upstreams                     []string      `flag:"upstream" cfg:"upstreams"`
}

func legacyUpstreamsFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("upstreams", pflag.ExitOnError)

	flagSet.Duration("flush-interval", DefaultUpstreamFlushInterval, "period between response flushing when streaming responses")
	flagSet.Bool("pass-host-header", true, "pass the request Host Header to upstream")
	flagSet.Bool("proxy-websockets", true, "enables WebSocket proxying")
	flagSet.Bool("ssl-upstream-insecure-skip-verify", false, "skip validation of certificates presented when using HTTPS upstreams")
	flagSet.StringSlice("upstream", []string{}, "the http url(s) of the upstream endpoint, file:// paths for static files or static://<status_code> for static response. Routing is based on the path")

	return flagSet
}

func (l *LegacyUpstreams) convert() (UpstreamConfig, error) {
	upstreams := UpstreamConfig{}

	for _, upstreamString := range l.Upstreams {
		u, err := url.Parse(upstreamString)
		if err != nil {
			return UpstreamConfig{}, fmt.Errorf("could not parse upstream %q: %v", upstreamString, err)
		}

		if u.Path == "" {
			u.Path = "/"
		}

		flushInterval := Duration(l.FlushInterval)
		upstream := Upstream{
			ID:                    u.Path,
			Path:                  u.Path,
			URI:                   upstreamString,
			InsecureSkipTLSVerify: l.SSLUpstreamInsecureSkipVerify,
			PassHostHeader:        &l.PassHostHeader,
			ProxyWebSockets:       &l.ProxyWebSockets,
			FlushInterval:         &flushInterval,
		}

		switch u.Scheme {
		case "file":
			if u.Fragment != "" {
				upstream.ID = u.Fragment
				upstream.Path = u.Fragment
				// Trim the fragment from the end of the URI
				upstream.URI = strings.SplitN(upstreamString, "#", 2)[0]
			}
		case "static":
			responseCode, err := strconv.Atoi(u.Host)
			if err != nil {
				logger.Errorf("unable to convert %q to int, use default \"200\"", u.Host)
				responseCode = 200
			}
			upstream.Static = true
			upstream.StaticCode = &responseCode

			// This is not allowed to be empty and must be unique
			upstream.ID = upstreamString

			// We only support the root path in the legacy config
			upstream.Path = "/"

			// Force defaults compatible with static responses
			upstream.URI = ""
			upstream.InsecureSkipTLSVerify = false
			upstream.PassHostHeader = nil
			upstream.ProxyWebSockets = nil
			upstream.FlushInterval = nil
		}

		upstreams.Upstreams = append(upstreams.Upstreams, upstream)
	}

	return upstreams, nil
}

type LegacyHeaders struct {
	PassBasicAuth     bool `flag:"pass-basic-auth" cfg:"pass_basic_auth"`
	PassAccessToken   bool `flag:"pass-access-token" cfg:"pass_access_token"`
	PassUserHeaders   bool `flag:"pass-user-headers" cfg:"pass_user_headers"`
	PassAuthorization bool `flag:"pass-authorization-header" cfg:"pass_authorization_header"`

	SetBasicAuth     bool `flag:"set-basic-auth" cfg:"set_basic_auth"`
	SetXAuthRequest  bool `flag:"set-xauthrequest" cfg:"set_xauthrequest"`
	SetAuthorization bool `flag:"set-authorization-header" cfg:"set_authorization_header"`

	PreferEmailToUser    bool   `flag:"prefer-email-to-user" cfg:"prefer_email_to_user"`
	BasicAuthPassword    string `flag:"basic-auth-password" cfg:"basic_auth_password"`
	SkipAuthStripHeaders bool   `flag:"skip-auth-strip-headers" cfg:"skip_auth_strip_headers"`
}

func legacyHeadersFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("headers", pflag.ExitOnError)

	flagSet.Bool("pass-basic-auth", true, "pass HTTP Basic Auth, X-Forwarded-User and X-Forwarded-Email information to upstream")
	flagSet.Bool("pass-access-token", false, "pass OAuth access_token to upstream via X-Forwarded-Access-Token header")
	flagSet.Bool("pass-user-headers", true, "pass X-Forwarded-User and X-Forwarded-Email information to upstream")
	flagSet.Bool("pass-authorization-header", false, "pass the Authorization Header to upstream")

	flagSet.Bool("set-basic-auth", false, "set HTTP Basic Auth information in response (useful in Nginx auth_request mode)")
	flagSet.Bool("set-xauthrequest", false, "set X-Auth-Request-User and X-Auth-Request-Email response headers (useful in Nginx auth_request mode)")
	flagSet.Bool("set-authorization-header", false, "set Authorization response headers (useful in Nginx auth_request mode)")

	flagSet.Bool("prefer-email-to-user", false, "Prefer to use the Email address as the Username when passing information to upstream. Will only use Username if Email is unavailable, eg. htaccess authentication. Used in conjunction with -pass-basic-auth and -pass-user-headers")
	flagSet.String("basic-auth-password", "", "the password to set when passing the HTTP Basic Auth header")
	flagSet.Bool("skip-auth-strip-headers", true, "strips X-Forwarded-* style authentication headers & Authorization header if they would be set by oauth2-proxy")

	return flagSet
}

// convert takes the legacy request/response headers and converts them to
// the new format for InjectRequestHeaders and InjectResponseHeaders
func (l *LegacyHeaders) convert() ([]Header, []Header) {
	return l.getRequestHeaders(), l.getResponseHeaders()
}

func (l *LegacyHeaders) getRequestHeaders() []Header {
	requestHeaders := []Header{}

	if l.PassBasicAuth && l.BasicAuthPassword != "" {
		requestHeaders = append(requestHeaders, getBasicAuthHeader(l.PreferEmailToUser, l.BasicAuthPassword))
	}

	// In the old implementation, PassUserHeaders is a subset of PassBasicAuth
	if l.PassBasicAuth || l.PassUserHeaders {
		requestHeaders = append(requestHeaders, getPassUserHeaders(l.PreferEmailToUser)...)
		requestHeaders = append(requestHeaders, getPreferredUsernameHeader())
	}

	if l.PassAccessToken {
		requestHeaders = append(requestHeaders, getPassAccessTokenHeader())
	}

	if l.PassAuthorization {
		requestHeaders = append(requestHeaders, getAuthorizationHeader())
	}

	for i := range requestHeaders {
		requestHeaders[i].PreserveRequestValue = !l.SkipAuthStripHeaders
	}

	return requestHeaders
}

func (l *LegacyHeaders) getResponseHeaders() []Header {
	responseHeaders := []Header{}

	if l.SetXAuthRequest {
		responseHeaders = append(responseHeaders, getXAuthRequestHeaders()...)
		if l.PassAccessToken {
			responseHeaders = append(responseHeaders, getXAuthRequestAccessTokenHeader())
		}
	}

	if l.SetBasicAuth {
		responseHeaders = append(responseHeaders, getBasicAuthHeader(l.PreferEmailToUser, l.BasicAuthPassword))
	}

	if l.SetAuthorization {
		responseHeaders = append(responseHeaders, getAuthorizationHeader())
	}

	return responseHeaders
}

func getBasicAuthHeader(preferEmailToUser bool, basicAuthPassword string) Header {
	claim := "user"
	if preferEmailToUser {
		claim = "email"
	}

	return Header{
		Name: "Authorization",
		Values: []HeaderValue{
			{
				ClaimSource: &ClaimSource{
					Claim:  claim,
					Prefix: "Basic ",
					BasicAuthPassword: &SecretSource{
						Value: []byte(basicAuthPassword),
					},
				},
			},
		},
	}
}

func getPassUserHeaders(preferEmailToUser bool) []Header {
	headers := []Header{
		{
			Name: "X-Forwarded-Groups",
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "groups",
					},
				},
			},
		},
	}

	if preferEmailToUser {
		return append(headers,
			Header{
				Name: "X-Forwarded-User",
				Values: []HeaderValue{
					{
						ClaimSource: &ClaimSource{
							Claim: "email",
						},
					},
				},
			},
		)
	}

	return append(headers,
		Header{
			Name: "X-Forwarded-User",
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "user",
					},
				},
			},
		},
		Header{
			Name: "X-Forwarded-Email",
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "email",
					},
				},
			},
		},
	)
}

func getPassAccessTokenHeader() Header {
	return Header{
		Name: "X-Forwarded-Access-Token",
		Values: []HeaderValue{
			{
				ClaimSource: &ClaimSource{
					Claim: "access_token",
				},
			},
		},
	}
}

func getAuthorizationHeader() Header {
	return Header{
		Name: "Authorization",
		Values: []HeaderValue{
			{
				ClaimSource: &ClaimSource{
					Claim:  "id_token",
					Prefix: "Bearer ",
				},
			},
		},
	}
}

func getPreferredUsernameHeader() Header {
	return Header{
		Name: "X-Forwarded-Preferred-Username",
		Values: []HeaderValue{
			{
				ClaimSource: &ClaimSource{
					Claim: "preferred_username",
				},
			},
		},
	}
}

func getXAuthRequestHeaders() []Header {
	headers := []Header{
		{
			Name: "X-Auth-Request-User",
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "user",
					},
				},
			},
		},
		{
			Name: "X-Auth-Request-Email",
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "email",
					},
				},
			},
		},
		{
			Name: "X-Auth-Request-Preferred-Username",
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "preferred_username",
					},
				},
			},
		},
		{
			Name: "X-Auth-Request-Groups",
			Values: []HeaderValue{
				{
					ClaimSource: &ClaimSource{
						Claim: "groups",
					},
				},
			},
		},
	}

	return headers
}

func getXAuthRequestAccessTokenHeader() Header {
	return Header{
		Name: "X-Auth-Request-Access-Token",
		Values: []HeaderValue{
			{
				ClaimSource: &ClaimSource{
					Claim: "access_token",
				},
			},
		},
	}
}

type LegacyServer struct {
	MetricsAddress       string `flag:"metrics-address" cfg:"metrics_address"`
	MetricsSecureAddress string `flag:"metrics-secure-address" cfg:"metrics_secure_address"`
	MetricsTLSCertFile   string `flag:"metrics-tls-cert-file" cfg:"metrics_tls_cert_file"`
	MetricsTLSKeyFile    string `flag:"metrics-tls-key-file" cfg:"metrics_tls_key_file"`
	HTTPAddress          string `flag:"http-address" cfg:"http_address"`
	HTTPSAddress         string `flag:"https-address" cfg:"https_address"`
	TLSCertFile          string `flag:"tls-cert-file" cfg:"tls_cert_file"`
	TLSKeyFile           string `flag:"tls-key-file" cfg:"tls_key_file"`
}

func legacyServerFlagset() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("server", pflag.ExitOnError)

	flagSet.String("metrics-address", "", "the address /metrics will be served on (e.g. \":9100\")")
	flagSet.String("metrics-secure-address", "", "the address /metrics will be served on for HTTPS clients (e.g. \":9100\")")
	flagSet.String("metrics-tls-cert-file", "", "path to certificate file for secure metrics server")
	flagSet.String("metrics-tls-key-file", "", "path to private key file for secure metrics server")
	flagSet.String("http-address", "127.0.0.1:4180", "[http://]<addr>:<port> or unix://<path> to listen on for HTTP clients")
	flagSet.String("https-address", ":443", "<addr>:<port> to listen on for HTTPS clients")
	flagSet.String("tls-cert-file", "", "path to certificate file")
	flagSet.String("tls-key-file", "", "path to private key file")

	return flagSet
}

type LegacyProvider struct {
	ClientID         string `flag:"client-id" cfg:"client_id"`
	ClientSecret     string `flag:"client-secret" cfg:"client_secret"`
	ClientSecretFile string `flag:"client-secret-file" cfg:"client_secret_file"`

	KeycloakGroups           []string `flag:"keycloak-group" cfg:"keycloak_groups"`
	AzureTenant              string   `flag:"azure-tenant" cfg:"azure_tenant"`
	BitbucketTeam            string   `flag:"bitbucket-team" cfg:"bitbucket_team"`
	BitbucketRepository      string   `flag:"bitbucket-repository" cfg:"bitbucket_repository"`
	GitHubOrg                string   `flag:"github-org" cfg:"github_org"`
	GitHubTeam               string   `flag:"github-team" cfg:"github_team"`
	GitHubRepo               string   `flag:"github-repo" cfg:"github_repo"`
	GitHubToken              string   `flag:"github-token" cfg:"github_token"`
	GitHubUsers              []string `flag:"github-user" cfg:"github_users"`
	GitLabGroup              []string `flag:"gitlab-group" cfg:"gitlab_groups"`
	GitLabProjects           []string `flag:"gitlab-project" cfg:"gitlab_projects"`
	GoogleGroups             []string `flag:"google-group" cfg:"google_group"`
	GoogleAdminEmail         string   `flag:"google-admin-email" cfg:"google_admin_email"`
	GoogleServiceAccountJSON string   `flag:"google-service-account-json" cfg:"google_service_account_json"`

	// These options allow for other providers besides Google, with
	// potential overrides.
	ProviderType                       string   `flag:"provider" cfg:"provider"`
	ProviderName                       string   `flag:"provider-display-name" cfg:"provider_display_name"`
	ProviderCAFiles                    []string `flag:"provider-ca-file" cfg:"provider_ca_files"`
	OIDCIssuerURL                      string   `flag:"oidc-issuer-url" cfg:"oidc_issuer_url"`
	InsecureOIDCAllowUnverifiedEmail   bool     `flag:"insecure-oidc-allow-unverified-email" cfg:"insecure_oidc_allow_unverified_email"`
	InsecureOIDCSkipIssuerVerification bool     `flag:"insecure-oidc-skip-issuer-verification" cfg:"insecure_oidc_skip_issuer_verification"`
	InsecureOIDCSkipNonce              bool     `flag:"insecure-oidc-skip-nonce" cfg:"insecure_oidc_skip_nonce"`
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
	AllowedRoles                       []string `flag:"allowed-role" cfg:"allowed_roles"`

	AcrValues  string `flag:"acr-values" cfg:"acr_values"`
	JWTKey     string `flag:"jwt-key" cfg:"jwt_key"`
	JWTKeyFile string `flag:"jwt-key-file" cfg:"jwt_key_file"`
	PubJWKURL  string `flag:"pubjwk-url" cfg:"pubjwk_url"`
}

func legacyProviderFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("provider", pflag.ExitOnError)

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

	flagSet.String("provider", "google", "OAuth provider")
	flagSet.String("provider-display-name", "", "Provider display name")
	flagSet.StringSlice("provider-ca-file", []string{}, "One or more paths to CA certificates that should be used when connecting to the provider.  If not specified, the default Go trust sources are used instead.")
	flagSet.String("oidc-issuer-url", "", "OpenID Connect issuer URL (ie: https://accounts.google.com)")
	flagSet.Bool("insecure-oidc-allow-unverified-email", false, "Don't fail if an email address in an id_token is not verified")
	flagSet.Bool("insecure-oidc-skip-issuer-verification", false, "Do not verify if issuer matches OIDC discovery URL")
	flagSet.Bool("insecure-oidc-skip-nonce", true, "skip verifying the OIDC ID Token's nonce claim")
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

	flagSet.String("acr-values", "", "acr values string:  optional")
	flagSet.String("jwt-key", "", "private key in PEM format used to sign JWT, so that you can say something like -jwt-key=\"${OAUTH2_PROXY_JWT_KEY}\": required by login.gov")
	flagSet.String("jwt-key-file", "", "path to the private key file in PEM format used to sign the JWT so that you can say something like -jwt-key-file=/etc/ssl/private/jwt_signing_key.pem: required by login.gov")
	flagSet.String("pubjwk-url", "", "JWK pubkey access endpoint: required by login.gov")

	flagSet.String("user-id-claim", providers.OIDCEmailClaim, "(DEPRECATED for `oidc-email-claim`) which claim contains the user ID")
	flagSet.StringSlice("allowed-group", []string{}, "restrict logins to members of this group (may be given multiple times)")
	flagSet.StringSlice("allowed-role", []string{}, "(keycloak-oidc) restrict logins to members of these roles (may be given multiple times)")

	return flagSet
}

func (l LegacyServer) convert() (Server, Server) {
	appServer := Server{
		BindAddress:       l.HTTPAddress,
		SecureBindAddress: l.HTTPSAddress,
	}
	if l.TLSKeyFile != "" || l.TLSCertFile != "" {
		appServer.TLS = &TLS{
			Key: &SecretSource{
				FromFile: l.TLSKeyFile,
			},
			Cert: &SecretSource{
				FromFile: l.TLSCertFile,
			},
		}
		// Preserve backwards compatibility, only run one server
		appServer.BindAddress = ""
	} else {
		// Disable the HTTPS server if there's no certificates.
		// This preserves backwards compatibility.
		appServer.SecureBindAddress = ""
	}

	metricsServer := Server{
		BindAddress:       l.MetricsAddress,
		SecureBindAddress: l.MetricsSecureAddress,
	}
	if l.MetricsTLSKeyFile != "" || l.MetricsTLSCertFile != "" {
		metricsServer.TLS = &TLS{
			Key: &SecretSource{
				FromFile: l.MetricsTLSKeyFile,
			},
			Cert: &SecretSource{
				FromFile: l.MetricsTLSCertFile,
			},
		}
	}

	return appServer, metricsServer
}

func (l *LegacyProvider) convert() (Providers, error) {
	providers := Providers{}

	provider := Provider{
		ClientID:          l.ClientID,
		ClientSecret:      l.ClientSecret,
		ClientSecretFile:  l.ClientSecretFile,
		Type:              l.ProviderType,
		CAFiles:           l.ProviderCAFiles,
		LoginURL:          l.LoginURL,
		RedeemURL:         l.RedeemURL,
		ProfileURL:        l.ProfileURL,
		ProtectedResource: l.ProtectedResource,
		ValidateURL:       l.ValidateURL,
		Scope:             l.Scope,
		Prompt:            l.Prompt,
		ApprovalPrompt:    l.ApprovalPrompt,
		AllowedGroups:     l.AllowedGroups,
		AcrValues:         l.AcrValues,
	}

	// This part is out of the switch section for all providers that support OIDC
	provider.OIDCConfig = OIDCOptions{
		IssuerURL:                      l.OIDCIssuerURL,
		InsecureAllowUnverifiedEmail:   l.InsecureOIDCAllowUnverifiedEmail,
		InsecureSkipIssuerVerification: l.InsecureOIDCSkipIssuerVerification,
		InsecureSkipNonce:              l.InsecureOIDCSkipNonce,
		SkipDiscovery:                  l.SkipOIDCDiscovery,
		JwksURL:                        l.OIDCJwksURL,
		UserIDClaim:                    l.UserIDClaim,
		EmailClaim:                     l.OIDCEmailClaim,
		GroupsClaim:                    l.OIDCGroupsClaim,
	}

	// This part is out of the switch section because azure has a default tenant
	// that needs to be added from legacy options
	provider.AzureConfig = AzureOptions{
		Tenant: l.AzureTenant,
	}

	switch provider.Type {
	case "github":
		provider.GitHubConfig = GitHubOptions{
			Org:   l.GitHubOrg,
			Team:  l.GitHubTeam,
			Repo:  l.GitHubRepo,
			Token: l.GitHubToken,
			Users: l.GitHubUsers,
		}
	case "keycloak-oidc":
		provider.KeycloakConfig = KeycloakOptions{
			Groups: l.KeycloakGroups,
			Roles:  l.AllowedRoles,
		}
	case "keycloak":
		provider.KeycloakConfig = KeycloakOptions{
			Groups: l.KeycloakGroups,
		}
	case "gitlab":
		provider.GitLabConfig = GitLabOptions{
			Group:    l.GitLabGroup,
			Projects: l.GitLabProjects,
		}
	case "login.gov":
		provider.LoginGovConfig = LoginGovOptions{
			JWTKey:     l.JWTKey,
			JWTKeyFile: l.JWTKeyFile,
			PubJWKURL:  l.PubJWKURL,
		}
	case "bitbucket":
		provider.BitbucketConfig = BitbucketOptions{
			Team:       l.BitbucketTeam,
			Repository: l.BitbucketRepository,
		}
	case "google":
		provider.GoogleConfig = GoogleOptions{
			Groups:             l.GoogleGroups,
			AdminEmail:         l.GoogleAdminEmail,
			ServiceAccountJSON: l.GoogleServiceAccountJSON,
		}
	}

	if l.ProviderName != "" {
		provider.ID = l.ProviderName
		provider.Name = l.ProviderName
	} else {
		provider.ID = l.ProviderType + "=" + l.ClientID
	}

	providers = append(providers, provider)

	return providers, nil
}
