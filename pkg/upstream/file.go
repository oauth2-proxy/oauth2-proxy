package upstream

import (
	"net/http"
	"net/url"
	"runtime"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
)

const fileScheme = "file"

// newFileServer creates a new fileServer that can serve requests
// to a file system location.
func newFileServer(upstream options.Upstream, fileSystemPath string) http.Handler {
	handler := newFileServerForPath(fileSystemPath)

	if upstream.RewriteTarget == "" {
		// if the upstream does not have a rewrite target, strip off the Path prefix
		// (so e.g. a request for /static/some-file.html looks for some-file.html
		// relative to the fileSystemPath rather than static/some-file.html).
		handler = http.StripPrefix(upstream.Path, handler)
	} else {
		// if the upstream *does* have a rewrite target then that means the target
		// path relative to the fileSystemPath will be the one in the (rewritten)
		// RequestURI.
		handler = requestURIToURL(handler)
	}
	return &fileServer{
		upstream: upstream.ID,
		handler:  handler,
	}
}

// newFileServerForPath creates a http.Handler to serve files from the filesystem
func newFileServerForPath(filesystemPath string) http.Handler {
	// Windows fileSSystemPath will be be prefixed with `/`, eg`/C:/...,
	// if they were parsed by url.Parse`
	if runtime.GOOS == "windows" {
		filesystemPath = strings.TrimPrefix(filesystemPath, "/")
	}

	return http.FileServer(http.Dir(filesystemPath))
}

// requestURIToURL returns a Handler that replaces the URL in its request with
// the result of parsing req.RequestURI.  This is necessary for file handlers
// that have a rewrite target, since http.FileServer uses req.URL.Path when
// looking for the target file, but the rewrite handler only updates the
// RequestURI, leaving the original path in the URL.
func requestURIToURL(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		reqURL, err := url.ParseRequestURI(req.RequestURI)
		if err != nil {
			http.Error(rw, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}

		req.URL = reqURL
		handler.ServeHTTP(rw, req)
	})
}

// fileServer represents a single filesystem upstream proxy
type fileServer struct {
	upstream string
	handler  http.Handler
}

// ServeHTTP proxies requests to the upstream provider while signing the
// request headers
func (u *fileServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	scope := middleware.GetRequestScope(req)
	// If scope is nil, this will panic.
	// A scope should always be injected before this handler is called.
	scope.Upstream = u.upstream

	u.handler.ServeHTTP(rw, req)
}
