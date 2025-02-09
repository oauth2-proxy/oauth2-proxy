package options

// AlphaOptions contains alpha structured configuration options.
// Usage of these options allows users to access alpha features that are not
// available as part of the primary configuration structure for OAuth2 Proxy.
//
// :::warning
// The options within this structure are considered alpha.
// They may change between releases without notice.
// :::
type AlphaOptions struct {
	// UpstreamConfig is used to configure upstream servers.
	// Once a user is authenticated, requests to the server will be proxied to
	// these upstream servers based on the path mappings defined in this list.
	UpstreamConfig UpstreamConfig `yaml:"upstreamConfig,omitempty"`

	// InjectRequestHeaders is used to configure headers that should be added
	// to requests to upstream servers.
	// Headers may source values from either the authenticated user's session
	// or from a static secret value.
	InjectRequestHeaders []Header `yaml:"injectRequestHeaders,omitempty"`

	// InjectResponseHeaders is used to configure headers that should be added
	// to responses from the proxy.
	// This is typically used when using the proxy as an external authentication
	// provider in conjunction with another proxy such as NGINX and its
	// auth_request module.
	// Headers may source values from either the authenticated user's session
	// or from a static secret value.
	InjectResponseHeaders []Header `yaml:"injectResponseHeaders,omitempty"`

	// Server is used to configure the HTTP(S) server for the proxy application.
	// You may choose to run both HTTP and HTTPS servers simultaneously.
	// This can be done by setting the BindAddress and the SecureBindAddress simultaneously.
	// To use the secure server you must configure a TLS certificate and key.
	Server Server `yaml:"server,omitempty"`

	// MetricsServer is used to configure the HTTP(S) server for metrics.
	// You may choose to run both HTTP and HTTPS servers simultaneously.
	// This can be done by setting the BindAddress and the SecureBindAddress simultaneously.
	// To use the secure server you must configure a TLS certificate and key.
	MetricsServer Server `yaml:"metricsServer,omitempty"`

	// Providers is used to configure your provider. **Multiple-providers is not
	// yet working.** [This feature is tracked in
	// #925](https://github.com/oauth2-proxy/oauth2-proxy/issues/926)
	Providers Providers `yaml:"providers,omitempty"`
}

// Initialize alpha options with default values and settings of the core options
func NewAlphaOptions(opts *Options) *AlphaOptions {
	aOpts := &AlphaOptions{}
	aOpts.ExtractFrom(opts)
	return aOpts
}

// ExtractFrom populates the fields in the AlphaOptions with the values from
// the Options
func (a *AlphaOptions) ExtractFrom(opts *Options) {
	a.UpstreamConfig = opts.UpstreamServers
	a.InjectRequestHeaders = opts.InjectRequestHeaders
	a.InjectResponseHeaders = opts.InjectResponseHeaders
	a.Server = opts.Server
	a.MetricsServer = opts.MetricsServer
	a.Providers = opts.Providers
}

// MergeInto replaces alpha options in the Options struct with the values
// from the AlphaOptions
func (a *AlphaOptions) MergeInto(opts *Options) {
	opts.UpstreamServers = a.UpstreamConfig
	opts.InjectRequestHeaders = a.InjectRequestHeaders
	opts.InjectResponseHeaders = a.InjectResponseHeaders
	opts.Server = a.Server
	opts.MetricsServer = a.MetricsServer
	opts.Providers = a.Providers
}
