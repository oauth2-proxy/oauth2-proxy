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
	ProxyOptions ProxyOptions `cfg:",internal"`

	PingPath      string `flag:"ping-path" cfg:"ping_path"`
	PingUserAgent string `flag:"ping-user-agent" cfg:"ping_user_agent"`
	ReadyPath     string `flag:"ready-path" cfg:"ready_path"`

	Cookie    Cookie         `cfg:",internal"`
	Session   SessionOptions `cfg:",squash"`
	Logging   Logging        `cfg:",squash"`
	Templates Templates      `cfg:",squash"`

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
		Cookie:       cookieDefaults(),
		Session:      sessionOptionsDefaults(),
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
	flagSet.String("session-store-type", "cookie", "the session storage provider to use")
	flagSet.Bool("session-cookie-minimal", false, "strip OAuth tokens from cookie session stores if they aren't needed (cookie session store only)")
	flagSet.String("redis-connection-url", "", "URL of redis server for redis session storage (eg: redis://[USER[:PASSWORD]@]HOST[:PORT])")
	flagSet.String("redis-username", "", "Redis username. Applicable for Redis configurations where ACL has been configured. Will override any username set in `--redis-connection-url`")
	flagSet.String("redis-password", "", "Redis password. Applicable for all Redis configurations. Will override any password set in `--redis-connection-url`")
	flagSet.Bool("redis-use-sentinel", false, "Connect to redis via sentinels. Must set --redis-sentinel-master-name and --redis-sentinel-connection-urls to use this feature")
	flagSet.String("redis-sentinel-password", "", "Redis sentinel password. Used only for sentinel connection; any redis node passwords need to use `--redis-password`")
	flagSet.String("redis-sentinel-master-name", "", "Redis sentinel master name. Used in conjunction with --redis-use-sentinel")
	flagSet.String("redis-ca-path", "", "Redis custom CA path")
	flagSet.Bool("redis-insecure-skip-tls-verify", false, "Use insecure TLS connection to redis")
	flagSet.StringSlice("redis-sentinel-connection-urls", []string{}, "List of Redis sentinel connection URLs (eg redis://[USER[:PASSWORD]@]HOST[:PORT]). Used in conjunction with --redis-use-sentinel")
	flagSet.Bool("redis-use-cluster", false, "Connect to redis cluster. Must set --redis-cluster-connection-urls to use this feature")
	flagSet.StringSlice("redis-cluster-connection-urls", []string{}, "List of Redis cluster connection URLs (eg redis://[USER[:PASSWORD]@]HOST[:PORT]). Used in conjunction with --redis-use-cluster")
	flagSet.Int("redis-connection-idle-timeout", 0, "Redis connection idle timeout seconds, if Redis timeout option is non-zero, the --redis-connection-idle-timeout must be less then Redis timeout option")
	flagSet.Bool("gcp-healthchecks", false, "Enable GCP/GKE healthcheck endpoints")

	flagSet.AddFlagSet(loggingFlagSet())
	flagSet.AddFlagSet(templatesFlagSet())

	return flagSet
}
