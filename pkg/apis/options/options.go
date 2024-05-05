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
	// ProxyOptions is used to configure the proxy behaviour.
	// This includes things like the prefix for protected paths, authentication
	// and routing options.
	ProxyOptions ProxyOptions `cfg:",internal"`

	// ProbeOptions is used to configure the probe endpoint for health and readiness checks.
	ProbeOptions ProbeOptions `cfg:",internal"`

	// Cookie is used to configure the cookie used to store the session state.
	// This includes options such as the cookie name, its expiry and its domain.
	Cookie Cookie `cfg:",internal"`

	// Session is used to configure the session storage.
	// To either use a cookie or a redis store.
	Session SessionOptions `cfg:",internal"`

	// Logging is used to configure the logging output.
	// Which formats are enabled and where to write the logs.
	Logging Logging `cfg:",internal"`

	// PageTemplates is used to configure custom page templates.
	// This includes the sign in and error pages.
	PageTemplates PageTemplates `cfg:",internal"`

	// Not used in the legacy config, name not allowed to match an external key (upstreams)
	// TODO(JoelSpeed): Rename when legacy config is removed
	UpstreamServers UpstreamConfig `cfg:",internal"`

	InjectRequestHeaders  []Header `cfg:",internal"`
	InjectResponseHeaders []Header `cfg:",internal"`

	Server        Server `cfg:",internal"`
	MetricsServer Server `cfg:",internal"`

	Providers Providers `cfg:",internal"`

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
		Providers:     providerDefaults(),
		Cookie:        cookieDefaults(),
		Session:       sessionOptionsDefaults(),
		PageTemplates: pageTemplatesDefaults(),
		Logging:       loggingDefaults(),
	}
}

// NewFlagSet creates a new FlagSet with all of the flags required by Options
// Deprecated: NewFlagSet is deprecated. Flags will be removed in v8.
func NewFlagSet() *pflag.FlagSet {
	return pflag.NewFlagSet("oauth2-proxy", pflag.ExitOnError)
}
