package upstream

import (
	"net/http"
)

// TrimRequestURIPath returns a handler that serves HTTP requests by removing
// the given prefix from the request URL's Path, RawPath (if set), and RequestURI
// before passing the request object on to the handler h. Apart from the change
// to the RequestURI, TrimRequestURIPath is also different from http.StripPath
// in that it does not reply with HTTP 404 if the request path does not start
// with the specified prefix.
func TrimRequestURIPath(prefix string, h http.Handler) http.Handler {
	if prefix == "" {
		return h
	}

	handler := func(w http.ResponseWriter, r *http.Request) {
		req := trimRequestURIPath(r, prefix)

		h.ServeHTTP(w, req)
	}

	return http.HandlerFunc(handler)
}

// trimRequestURIPath remove the given prefix from the request RequestURI,
// URL Path and URL RawPath. prefix is expected to have no trailing slash
// in order for it to be able to trim the prefix from request paths which
// do not have one either.
func trimRequestURIPath(req *http.Request, prefix string) (res *http.Request) {
	var path, rawPath string

	sub := prefix + "/"
	cut := len(prefix)
	res = req

	if req.URL.Path == prefix { // http://host/prefix
		path = "/"
	} else if len(req.URL.Path) >= cut && req.URL.Path[0:cut+1] == sub { // http://host/prefix/
		path = req.URL.Path[cut:]
	}

	if req.URL.RawPath == prefix {
		rawPath = "/"
	} else if len(req.URL.RawPath) >= cut && req.URL.RawPath[0:cut+1] == sub {
		rawPath = req.URL.RawPath[cut:]
		// this block is strings.HasPrefix and strings.TrimPrefix
		// combined, with the difference, that it does not return
		// the input if it does not start with the given prefix
	}

	if path != "" || rawPath != "" {
		res = req.Clone(req.Context())
		res.URL.Path = path
		res.URL.RawPath = rawPath
		res.RequestURI = res.URL.String()
	}

	return
}
