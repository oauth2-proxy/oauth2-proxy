package conditions

import (
	"net/http"
	"strings"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
)

type methods struct {
	methods map[string]struct{}
}

// NewMethods takes a list of methods and creates the methods field set
func NewMethods(httpMethods []string) Condition {
	ms := map[string]struct{}{}
	for _, method := range httpMethods {
		ms[strings.ToUpper(method)] = struct{}{}
	}
	return &methods{
		methods: ms,
	}
}

// Match does a set membership test of the request method
func (m *methods) Match(req *http.Request, _ *sessions.SessionState) bool {
	if req == nil {
		return false
	}
	if _, ok := m.methods[req.Method]; ok {
		return true
	}
	return false
}
