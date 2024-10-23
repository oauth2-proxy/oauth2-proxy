package options

import "time"

const (
	// DefaultUpstreamFlushInterval is the default value for the Upstream FlushInterval.
	DefaultUpstreamFlushInterval = 1 * time.Second

	// DefaultUpstreamTimeout is the maximum duration a network dial to a upstream server for a response.
	DefaultUpstreamTimeout = 30 * time.Second
)

// UpstreamConfig is a collection of definitions for upstream servers.
type UpstreamConfig struct {
	// ProxyRawPath will pass the raw url path to upstream allowing for urls
	// like: "/%2F/" which would otherwise be redirected to "/"
	ProxyRawPath bool `json:"proxyRawPath,omitempty"`

	// Upstreams represents the configuration for the upstream servers.
	// Requests will be proxied to this upstream if the path matches the request path.
	Upstreams []Upstream `json:"upstreams,omitempty"`
}

// Upstream represents the configuration for an upstream server.
// Requests will be proxied to this upstream if the path matches the request path.
type Upstream struct {
	// ID should be a unique identifier for the upstream.
	// This value is required for all upstreams.
	ID string `json:"id,omitempty"`

	// Path is used to map requests to the upstream server.
	// The closest match will take precedence and all Paths must be unique.
	// Path can also take a pattern when used with RewriteTarget.
	// Path segments can be captured and matched using regular experessions.
	// Eg:
	// - `^/foo$`: Match only the explicit path `/foo`
	// - `^/bar/$`: Match any path prefixed with `/bar/`
	// - `^/baz/(.*)$`: Match any path prefixed with `/baz` and capture the remaining path for use with RewriteTarget
	Path string `json:"path,omitempty"`

	// RewriteTarget allows users to rewrite the request path before it is sent to
	// the upstream server (for an HTTP/HTTPS upstream) or mapped to the filesystem
	// (for a `file:` upstream).
	// Use the Path to capture segments for reuse within the rewrite target.
	// Eg: With a Path of `^/baz/(.*)`, a RewriteTarget of `/foo/$1` would rewrite
	// the request `/baz/abc/123` to `/foo/abc/123` before proxying to the
	// upstream server.  Or if the upstream were `file:///app`, a request for
	// `/baz/info.html` would return the contents of the file `/app/foo/info.html`.
	RewriteTarget string `json:"rewriteTarget,omitempty"`

	// The URI of the upstream server. This may be an HTTP(S) server of a File
	// based URL. It may include a path, in which case all requests will be served
	// under that path.
	// Eg:
	// - http://localhost:8080
	// - https://service.localhost
	// - https://service.localhost/path
	// - file://host/path
	// If the URI's path is "/base" and the incoming request was for "/dir",
	// the upstream request will be for "/base/dir".
	URI string `json:"uri,omitempty"`

	// InsecureSkipTLSVerify will skip TLS verification of upstream HTTPS hosts.
	// This option is insecure and will allow potential Man-In-The-Middle attacks
	// between OAuth2 Proxy and the upstream server.
	// Defaults to false.
	InsecureSkipTLSVerify bool `json:"insecureSkipTLSVerify,omitempty"`

	// Static will make all requests to this upstream have a static response.
	// The response will have a body of "Authenticated" and a response code
	// matching StaticCode.
	// If StaticCode is not set, the response will return a 200 response.
	Static bool `json:"static,omitempty"`

	// StaticCode determines the response code for the Static response.
	// This option can only be used with Static enabled.
	StaticCode *int `json:"staticCode,omitempty"`

	// FlushInterval is the period between flushing the response buffer when
	// streaming response from the upstream.
	// Defaults to 1 second.
	FlushInterval *Duration `json:"flushInterval,omitempty"`

	// PassHostHeader determines whether the request host header should be proxied
	// to the upstream server.
	// Defaults to true.
	PassHostHeader *bool `json:"passHostHeader,omitempty"`

	// ProxyWebSockets enables proxying of websockets to upstream servers
	// Defaults to true.
	ProxyWebSockets *bool `json:"proxyWebSockets,omitempty"`

	// Timeout is the maximum duration the server will wait for a response from the upstream server.
	// Defaults to 30 seconds.
	Timeout *Duration `json:"timeout,omitempty"`
}
