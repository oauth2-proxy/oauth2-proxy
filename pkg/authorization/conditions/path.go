package conditions

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
)

type path struct {
	path *regexp.Regexp
}

// NewPath builds the PathRegex from a raw path regex string
func NewPath(pathRegex string) (Condition, error) {
	compiled, err := regexp.Compile(pathRegex)
	if err != nil {
		return nil, fmt.Errorf("error compiling regex /%s/: %v", pathRegex, err)
	}
	return &path{
		path: compiled,
	}, nil
}

// Match does a regex check against the request path
func (p *path) Match(req *http.Request, _ *sessions.SessionState) bool {
	if req == nil {
		return false
	}
	return p.path.MatchString(req.URL.Path)
}
