package upstream

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/gorilla/mux"
	"github.com/justinas/alice"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/app/pagewriter"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
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

	if upstreams.ProxyRawPath {
		m.serveMux.UseEncodedPath()
	}

	for _, upstream := range sortByPathLongest(upstreams.Upstreams) {
		if upstream.Static {
			if err := m.registerStaticResponseHandler(upstream, writer); err != nil {
				return nil, fmt.Errorf("could not register static upstream %q: %v", upstream.ID, err)
			}
			continue
		}

		u, err := url.Parse(upstream.URI)
		if err != nil {
			return nil, fmt.Errorf("error parsing URI for upstream %q: %w", upstream.ID, err)
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

	registerTrailingSlashHandler(m.serveMux)
	return m, nil
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
	logger.Printf("mapping path %q => static response %d", upstream.Path, derefStaticCode(upstream.StaticCode))
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
		m.registerSimpleHandler(upstream.Path, handler)
		return nil
	}

	return m.registerRewriteHandler(upstream, handler, writer)
}

// registerSimpleHandler maintains the behaviour of the go standard serveMux
// by ensuring any path with a trailing `/` matches all paths under that prefix.
func (m *multiUpstreamProxy) registerSimpleHandler(path string, handler http.Handler) {
	if strings.HasSuffix(path, "/") {
		m.serveMux.PathPrefix(path).Handler(handler)
	} else {
		m.serveMux.Path(path).Handler(handler)
	}
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
	m.serveMux.MatcherFunc(func(req *http.Request, _ *mux.RouteMatch) bool {
		return rewriteRegExp.MatchString(req.URL.Path)
	}).Handler(h)

	return nil
}

// registerTrailingSlashHandler creates a new matcher that will check if the
// requested path would match if it had a trailing slash appended.
// If the path matches with a trailing slash, we send back a redirect.
// This allows us to be consistent with the built in go servemux implementation.
func registerTrailingSlashHandler(serveMux *mux.Router) {
	serveMux.MatcherFunc(func(req *http.Request, _ *mux.RouteMatch) bool {
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
	}))
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
