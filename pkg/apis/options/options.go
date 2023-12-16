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
	ProxyOptions ProxyOptions `cfg:",internal" json:"proxyOptions,omitempty"`
	ProbeOptions ProbeOptions `cfg:",internal" json:"probeOptions,omitempty"`

	// Cookie is used to configure the cookie used to store the session state.
	Cookie Cookie `cfg:",internal" json:"cookie,omitempty"`

	Session SessionOptions `cfg:",internal" json:"session,omitempty"`

	Logging Logging `cfg:",internal" json:"logging,omitempty"`

	PageTemplates PageTemplates `cfg:",internal" json:"pageTemplates,omitempty"`

	// UpstreamConfig is used to configure upstream servers.
	// Once a user is authenticated, requests to the server will be proxied to
	// these upstream servers based on the path mappings defined in this list.
	//
	// Not used in the legacy config, name not allowed to match an external key (upstreams)
	// TODO(JoelSpeed): Rename when legacy config is removed
	UpstreamServers UpstreamConfig `cfg:",internal" json:"upstreamConfig,omitempty"`

	// InjectRequestHeaders is used to configure headers that should be added
	// to requests to upstream servers.
	// Headers may source values from either the authenticated user's session
	// or from a static secret value.
	InjectRequestHeaders []Header `cfg:",internal" json:"injectRequestHeaders,omitempty"`

	// InjectResponseHeaders is used to configure headers that should be added
	// to responses from the proxy.
	// This is typically used when using the proxy as an external authentication
	// provider in conjunction with another proxy such as NGINX and its
	// auth_request module.
	// Headers may source values from either the authenticated user's session
	// or from a static secret value.
	InjectResponseHeaders []Header `cfg:",internal" json:"injectResponseHeaders,omitempty"`

	// Server is used to configure the HTTP(S) server for the proxy application.
	// You may choose to run both HTTP and HTTPS servers simultaneously.
	// This can be done by setting the BindAddress and the SecureBindAddress simultaneously.
	// To use the secure server you must configure a TLS certificate and key.
	Server Server `cfg:",internal" json:"server,omitempty"`

	// MetricsServer is used to configure the HTTP(S) server for metrics.
	// You may choose to run both HTTP and HTTPS servers simultaneously.
	// This can be done by setting the BindAddress and the SecureBindAddress simultaneously.
	// To use the secure server you must configure a TLS certificate and key.
	MetricsServer Server `cfg:",internal" json:"metricsServer,omitempty"`

	// Providers is used to configure multiple providers.
	// As of yet multiple providers aren't supported only the first entry is actually used.
	Providers Providers `cfg:",internal" json:"providers,omitempty"`

	// Force oauth2-proxy error responses to be JSON
	ForceJSONErrors bool `json:"forceJsonErrors,omitempty"`

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
		ProxyOptions:  proxyOptionsDefaults(),
		ProbeOptions:  probeOptionsDefaults(),
		Cookie:        cookieDefaults(),
		Session:       sessionOptionsDefaults(),
		Logging:       loggingDefaults(),
		PageTemplates: pageTemplatesDefaults(),
		Providers:     providerDefaults(),
	}
}

func NewFlagSet() *pflag.FlagSet {
	return pflag.NewFlagSet("oauth2-proxy", pflag.ExitOnError)
}
