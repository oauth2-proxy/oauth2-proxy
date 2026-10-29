package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options/util"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/app/pagewriter"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/util/ptr"
)

// ProxyErrorHandler is a function that will be used to render error pages when
// HTTP proxies fail to connect to upstream servers.
type ProxyErrorHandler func(http.ResponseWriter, *http.Request, error)

// NewProxy creates a new multiUpstreamProxy that can serve requests directed to
// multiple upstreams.
func NewProxy(upstreams options.UpstreamConfig, sigData *options.SignatureData, writer pagewriter.Writer) (http.Handler, error) {
	m := &multiUpstreamProxy{
		serveMux: mux.NewRouter(),
	}

	if ptr.Deref(upstreams.ProxyRawPath, options.DefaultUpstreamProxyRawPath) {
		m.serveMux.UseEncodedPath()
	}

	for _, upstream := range sortByPathLongest(upstreams.Upstreams) {
		if ptr.Deref(upstream.Static, options.DefaultUpstreamStatic) {
			if upstream.RootCA != nil || upstream.ClientCert != nil || upstream.ClientKey != nil {
				return nil, fmt.Errorf("TLS options cannot be used with static upstream %q", upstream.ID)
			}
			if err := m.registerStaticResponseHandler(upstream, writer); err != nil {
				return nil, fmt.Errorf("could not register static upstream %q: %v", upstream.ID, err)
			}
			continue
		}

		u, err := url.Parse(upstream.URI)
		if err != nil {
			return nil, fmt.Errorf("error parsing URI for upstream %q: %w", upstream.ID, err)
		}
		if err := prepareUpstreamTLS(&upstream, u); err != nil {
			return nil, fmt.Errorf("invalid TLS configuration for upstream %q: %w", upstream.ID, err)
		}
		switch u.Scheme {
		case fileScheme:
			if err := m.registerFileServer(upstream, u, writer); err != nil {
				return nil, fmt.Errorf("could not register file upstream %q: %v", upstream.ID, err)
			}
		case httpScheme, httpsScheme, unixScheme:
			if err := m.registerHTTPUpstreamProxy(upstream, u, sigData, writer); err != nil {
				return nil, fmt.Errorf("could not register %s upstream %q: %v", u.Scheme, upstream.ID, err)
			}
		default:
			return nil, fmt.Errorf("unknown scheme for upstream %q: %q", upstream.ID, u.Scheme)
		}
	}

	if err := registerTrailingSlashHandler(m.serveMux); err != nil {
		return nil, fmt.Errorf("could not register trailing slash handler: %w", err)
	}
	return m, nil
}

func prepareUpstreamTLS(upstream *options.Upstream, target *url.URL) error {
	if upstream.RootCA == nil && upstream.ClientCert == nil && upstream.ClientKey == nil {
		return nil
	}
	if target.Scheme != httpsScheme {
		return fmt.Errorf("TLS options require an https upstream")
	}
	if ptr.Deref(upstream.InsecureSkipTLSVerify, options.DefaultUpsteamInsecureSkipTLSVerify) {
		return fmt.Errorf("TLS options cannot be combined with insecureSkipTLSVerify")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12} // #nosec G402 -- verification remains enabled
	if upstream.RootCA != nil {
		data, err := util.GetSecretValue(upstream.RootCA)
		if err != nil {
			return fmt.Errorf("load root CA: %w", err)
		}
		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(data); !ok {
			return fmt.Errorf("root CA does not contain a valid PEM certificate")
		}
		config.RootCAs = pool
	}
	if (upstream.ClientCert == nil) != (upstream.ClientKey == nil) {
		return fmt.Errorf("clientCert and clientKey must be configured together")
	}
	if upstream.ClientCert != nil {
		certData, err := util.GetSecretValue(upstream.ClientCert)
		if err != nil {
			return fmt.Errorf("load client certificate: %w", err)
		}
		keyData, err := util.GetSecretValue(upstream.ClientKey)
		if err != nil {
			return fmt.Errorf("load client key: %w", err)
		}
		cert, err := tls.X509KeyPair(certData, keyData)
		if err != nil {
			return fmt.Errorf("load client certificate: %w", err)
		}
		config.Certificates = []tls.Certificate{cert}
	}
	upstream.SetTLSClientConfig(config)
	return nil
}

// multiUpstreamProxy will serve requests directed to multiple upstream servers
// registered in the serverMux.
type multiUpstreamProxy struct {
	serveMux *mux.Router
}

// ServerHTTP handles HTTP requests.
func (m *multiUpstreamProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	m.serveMux.ServeHTTP(rw, req)
}

// registerStaticResponseHandler registers a static response handler with at the given path.
func (m *multiUpstreamProxy) registerStaticResponseHandler(upstream options.Upstream, writer pagewriter.Writer) error {
	logger.Printf("mapping path %q => static response %d", upstream.Path, ptr.Deref(upstream.StaticCode, options.DefaultUpstreamStaticCode))
	return m.registerHandler(upstream, newStaticResponseHandler(upstream.ID, upstream.StaticCode), writer)
}

// registerFileServer registers a new fileServer based on the configuration given.
func (m *multiUpstreamProxy) registerFileServer(upstream options.Upstream, u *url.URL, writer pagewriter.Writer) error {
	logger.Printf("mapping path %q => file system %q", upstream.Path, u.Path)
	return m.registerHandler(upstream, newFileServer(upstream, u.Path), writer)
}

// registerHTTPUpstreamProxy registers a new httpUpstreamProxy based on the configuration given.
func (m *multiUpstreamProxy) registerHTTPUpstreamProxy(upstream options.Upstream, u *url.URL, sigData *options.SignatureData, writer pagewriter.Writer) error {
	logger.Printf("mapping path %q => upstream %q", upstream.Path, upstream.URI)
	return m.registerHandler(upstream, newHTTPUpstreamProxy(upstream, u, sigData, writer.ProxyErrorHandler), writer)
}

// registerHandler ensures the given handler is regiestered with the serveMux.
func (m *multiUpstreamProxy) registerHandler(upstream options.Upstream, handler http.Handler, writer pagewriter.Writer) error {
	if upstream.RewriteTarget == "" {
		return m.registerSimpleHandler(upstream.Path, handler)
	}

	return m.registerRewriteHandler(upstream, handler, writer)
}

// registerSimpleHandler maintains the behaviour of the go standard serveMux
// by ensuring any path with a trailing `/` matches all paths under that prefix.
func (m *multiUpstreamProxy) registerSimpleHandler(path string, handler http.Handler) error {
	if strings.HasSuffix(path, "/") {
		return m.serveMux.PathPrefix(path).Handler(handler).GetError()
	}

	return m.serveMux.Path(path).Handler(handler).GetError()
}

// registerRewriteHandler ensures the handler is registered for all paths
// which match the regex defined in the Path.
// Requests to the handler will have the request path rewritten before the
// request is made to the next handler.
func (m *multiUpstreamProxy) registerRewriteHandler(upstream options.Upstream, handler http.Handler, writer pagewriter.Writer) error {
	rewriteRegExp, err := regexp.Compile(upstream.Path)
	if err != nil {
		return fmt.Errorf("invalid path %q for upstream: %v", upstream.Path, err)
	}

	rewrite := newRewritePath(rewriteRegExp, upstream.RewriteTarget, writer)
	h := alice.New(rewrite).Then(handler)

	return m.serveMux.MatcherFunc(func(req *http.Request, _ *mux.RouteMatch) bool {
		return rewriteRegExp.MatchString(req.URL.Path)
	}).Handler(h).GetError()
}

// registerTrailingSlashHandler creates a new matcher that will check if the
// requested path would match if it had a trailing slash appended.
// If the path matches with a trailing slash, we send back a redirect.
// This allows us to be consistent with the built in go servemux implementation.
func registerTrailingSlashHandler(serveMux *mux.Router) error {
	return serveMux.MatcherFunc(func(req *http.Request, _ *mux.RouteMatch) bool {
		if strings.HasSuffix(req.URL.Path, "/") {
			return false
		}

		// Use a separate RouteMatch so that we can redirect to the path + /.
		// If we pass through the match then the matched backed will be served
		// instead of the redirect handler.
		m := &mux.RouteMatch{}
		slashReq := req.Clone(context.Background())
		slashReq.URL.Path += "/"
		return serveMux.Match(slashReq, m)
	}).Handler(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		http.Redirect(rw, req, req.URL.String()+"/", http.StatusMovedPermanently)
	})).GetError()
}

// sortByPathLongest ensures that the upstreams are sorted by longest path.
// If rewrites are involved, a rewrite takes precedence over a non-rewrite.
// When two upstreams define rewrites, whichever has the longest path will take
// precedence (note this is the input to the rewrite logic).
// This does not account for when a rewrite would actually make the path shorter.
// This should maintain the sorting behaviour of the standard go serve mux.
func sortByPathLongest(in []options.Upstream) []options.Upstream {
	sort.Slice(in, func(i, j int) bool {
		iRW := in[i].RewriteTarget
		jRW := in[j].RewriteTarget

		switch {
		case iRW != "" && jRW != "":
			// If both have a rewrite target, whichever has the longest pattern
			// should go first
			return len(in[i].Path) > len(in[j].Path)
		case iRW != "" && jRW == "":
			// Only one has rewrite, it goes first
			return true
		case iRW == "" && jRW != "":
			// Only one has rewrite, it goes first
			return false
		default:
			// Default to longest Path wins
			return len(in[i].Path) > len(in[j].Path)
		}
	})
	return in
}
