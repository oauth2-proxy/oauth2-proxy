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
	PingPath      string `flag:"ping-path" cfg:"ping_path"`
	PingUserAgent string `flag:"ping-user-agent" cfg:"ping_user_agent"`
	ReadyPath     string `flag:"ready-path" cfg:"ready_path"`

	ProxyOptions ProxyOptions   `cfg:",internal"`
	Cookie       Cookie         `cfg:",internal"`
	Session      SessionOptions `cfg:",internal"`
	Logging      Logging        `cfg:",squash"`
	Templates    Templates      `cfg:",squash"`

	GCPHealthChecks bool `flag:"gcp-healthchecks" cfg:"gcp_healthchecks"`

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
		ProxyOptions: proxyOptionsDefaults(),
		Providers:    providerDefaults(),
		PingPath:     "/ping",
		ReadyPath:    "/ready",
		Templates:    templatesDefaults(),
		Logging:      loggingDefaults(),
	}
}

// NewFlagSet creates a new FlagSet with all of the flags required by Options
func NewFlagSet() *pflag.FlagSet {
	flagSet := pflag.NewFlagSet("oauth2-proxy", pflag.ExitOnError)

	flagSet.String("ping-path", "/ping", "the ping endpoint that can be used for basic health checks")
	flagSet.String("ping-user-agent", "", "special User-Agent that will be used for basic health checks")
	flagSet.String("ready-path", "/ready", "the ready endpoint that can be used for deep health checks")
	flagSet.Bool("gcp-healthchecks", false, "Enable GCP/GKE healthcheck endpoints")

	flagSet.AddFlagSet(loggingFlagSet())
	flagSet.AddFlagSet(templatesFlagSet())

	return flagSet
}

// EnsureDefaults configures the defaults for all options
// to ensure no unexpected empty strings for enum types or nils for booleans
func (o *Options) EnsureDefaults() {
	o.Providers.EnsureDefaults()
	o.UpstreamServers.EnsureDefaults()

	for i := range o.InjectRequestHeaders {
		o.InjectRequestHeaders[i].EnsureDefaults()
	}
	for i := range o.InjectResponseHeaders {
		o.InjectResponseHeaders[i].EnsureDefaults()
	}

	o.Cookie.EnsureDefaults()
	o.Session.EnsureDefaults()
	// TBD: Uncomment as we add EnsureDefaults methods
	// o.Templates.EnsureDefaults()
	// o.Logging.EnsureDefaults()
}
