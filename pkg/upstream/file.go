package upstream

import "net/http"

const fileScheme = "file"

// newFileServer creates a new fileServer that can serve requests
// to a file system location.
func newFileServer(id, path, fileSystemPath string) http.Handler {
	return &fileServer{
		upstream: id,
		handler:  newFileServerForPath(path, fileSystemPath),
	}
}

// newFileServerForPath creates a http.Handler to serve files from the filesystem
func newFileServerForPath(path string, filesystemPath string) http.Handler {
	return http.StripPrefix(path, http.FileServer(http.Dir(filesystemPath)))
}

// fileServer represents a single filesystem upstream proxy
type fileServer struct {
	upstream string
	handler  http.Handler
}

// ServeHTTP proxies requests to the upstream provider while signing the
// request headers
func (u *fileServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("GAP-Upstream-Address", u.upstream)
	u.handler.ServeHTTP(rw, req)
}
