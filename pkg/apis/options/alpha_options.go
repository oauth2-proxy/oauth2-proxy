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

	// MetricsServer is used to configure the HTTP(S) server for metrics.
	// You may choose to run both HTTP and HTTPS servers simultaneously.
	// This can be done by setting the BindAddress and the SecureBindAddress simultaneously.
	// To use the secure server you must configure a TLS certificate and key.
	MetricsServer Server `json:"metricsServer,omitempty"`

	// Providers is used to configure multiple providers.
	Providers Providers `json:"providers,omitempty"`

	// ProviderLoader is used to allow multiple providers in oauth2-proxy.
	// You can choose between single, config and postgres types.
	ProviderLoader ProviderLoader `json:"providerLoader,omitempty"`

	// ProviderMatcher is used to configure the provider-id matching rules for extracting provider-id from request
	// which will then in turn cause providerLoader to load provider/provider identifying from its ID.
	// The rules define where to look for provider-id in request header, host, query or path or their precedence.
	ProviderMatcher ProviderMatcher `json:"providerMatcher,omitempty"`
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
	opts.ProviderLoader = a.ProviderLoader
	opts.ProviderMatcher = a.ProviderMatcher
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
