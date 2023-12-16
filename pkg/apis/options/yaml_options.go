package options

// YamlOptions contains structured configuration options.
type YamlOptions struct {
	// UpstreamConfig is used to configure upstream servers.
	// Once a user is authenticated, requests to the server will be proxied to
	// these upstream servers based on the path mappings defined in this list.
	UpstreamConfig UpstreamConfig `json:"upstreamConfig,omitempty"`

	// InjectRequestHeaders is used to configure headers that should be added
	// to requests to upstream servers.
	// Headers may source values from either the authenticated user's session
	// or from a static secret value.
	InjectRequestHeaders []Header `json:"injectRequestHeaders,omitempty"`

	// InjectResponseHeaders is used to configure headers that should be added
	// to responses from the proxy.
	// This is typically used when using the proxy as an external authentication
	// provider in conjunction with another proxy such as NGINX and its
	// auth_request module.
	// Headers may source values from either the authenticated user's session
	// or from a static secret value.
	InjectResponseHeaders []Header `json:"injectResponseHeaders,omitempty"`

	// Server is used to configure the HTTP(S) server for the proxy application.
	// You may choose to run both HTTP and HTTPS servers simultaneously.
	// This can be done by setting the BindAddress and the SecureBindAddress simultaneously.
	// To use the secure server you must configure a TLS certificate and key.
	Server Server `json:"server,omitempty"`

	// Cookie is used to configure the cookie used to store the session state.
	Cookie Cookie `json:"cookie,omitempty"`

	Session SessionOptions `json:"session,omitempty"`

	Logging Logging `json:"logging,omitempty"`

	PageTemplates PageTemplates `json:"pageTemplates,omitempty"`

	ProxyOptions ProxyOptions `json:"proxyOptions,omitempty"`

	ProbeOptions ProbeOptions `json:"probeOptions,omitempty"`

	// MetricsServer is used to configure the HTTP(S) server for metrics.
	// You may choose to run both HTTP and HTTPS servers simultaneously.
	// This can be done by setting the BindAddress and the SecureBindAddress simultaneously.
	// To use the secure server you must configure a TLS certificate and key.
	MetricsServer Server `json:"metricsServer,omitempty"`

	// Providers is used to configure multiple providers.
	Providers Providers `json:"providers,omitempty"`
}

// MergeInto replaces options in the Options struct with the values
// from the YamlOptions
func (a *YamlOptions) MergeInto(opts *Options) {
	opts.UpstreamServers = a.UpstreamConfig
	opts.InjectRequestHeaders = a.InjectRequestHeaders
	opts.InjectResponseHeaders = a.InjectResponseHeaders
	opts.Server = a.Server
	opts.Cookie = a.Cookie
	opts.MetricsServer = a.MetricsServer
	opts.Providers = a.Providers
}

// ExtractFrom populates the fields in the YamlOptions with the values from
// the Options
func (a *YamlOptions) ExtractFrom(opts *Options) {
	a.UpstreamConfig = opts.UpstreamServers
	a.InjectRequestHeaders = opts.InjectRequestHeaders
	a.InjectResponseHeaders = opts.InjectResponseHeaders
	a.Server = opts.Server
	a.Cookie = opts.Cookie
	a.MetricsServer = opts.MetricsServer
	a.Providers = opts.Providers
}
