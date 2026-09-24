package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

// TestIsAllowedRoute_Decisions locks the skip-auth allow/deny outcomes of
// isAllowedRoute, including the fragment stripping that GetRequestPath
// performs, negated routes, and method-scoped routes that do not match.
func TestIsAllowedRoute_Decisions(t *testing.T) {
	route := func(method, pattern string, negate bool) allowedRoute {
		return allowedRoute{
			method:    method,
			negate:    negate,
			pathRegex: regexp.MustCompile(pattern),
		}
	}

	tests := []struct {
		name   string
		routes []allowedRoute
		method string
		target string
		want   bool
	}{
		{"no routes configured", nil, http.MethodGet, "/public", false},
		{"single route matches", []allowedRoute{route("", "^/public", false)}, http.MethodGet, "/public", true},
		{"single route misses", []allowedRoute{route("", "^/public", false)}, http.MethodGet, "/private", false},
		{"query string ignored", []allowedRoute{route("", "^/public$", false)}, http.MethodGet, "/public?a=1", true},
		{"fragment stripped before match", []allowedRoute{route("", "^/public$", false)}, http.MethodGet, "/public#/admin", true},
		{"fragment cannot smuggle a match", []allowedRoute{route("", "^/admin$", false)}, http.MethodGet, "/public#/admin", false},
		{"method matches", []allowedRoute{route(http.MethodPost, "^/hook", false)}, http.MethodPost, "/hook", true},
		{"method does not match", []allowedRoute{route(http.MethodPost, "^/hook", false)}, http.MethodGet, "/hook", false},
		{"all routes method-scoped and missing", []allowedRoute{
			route(http.MethodPost, "^/a", false),
			route(http.MethodPut, "^/b", false),
		}, http.MethodGet, "/a", false},
		{"negate allows non-matching path", []allowedRoute{route("", "^/private", true)}, http.MethodGet, "/public", true},
		{"negate denies matching path", []allowedRoute{route("", "^/private", true)}, http.MethodGet, "/private", false},
		{"first match wins across routes", []allowedRoute{
			route("", "^/nope", false),
			route("", "^/yes", false),
		}, http.MethodGet, "/yes", true},
		{"negate route followed by a matching route", []allowedRoute{
			route("", "^/private", true),
			route("", "^/private/ok", false),
		}, http.MethodGet, "/private/ok", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &OAuthProxy{allowedRoutes: tt.routes}
			req := httptest.NewRequest(tt.method, tt.target, nil)
			if got := p.isAllowedRoute(req); got != tt.want {
				t.Errorf("isAllowedRoute(%s %s) = %v, want %v", tt.method, tt.target, got, tt.want)
			}
		})
	}
}

func BenchmarkIsAllowedRoute(b *testing.B) {
	for _, n := range []int{1, 4, 16} {
		routes := make([]allowedRoute, n)
		for i := range routes {
			routes[i] = allowedRoute{pathRegex: regexp.MustCompile(fmt.Sprintf("^/never-matches-%d", i))}
		}
		p := &OAuthProxy{allowedRoutes: routes}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/resource?x=1", nil)
		b.Run(fmt.Sprintf("routes=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if p.isAllowedRoute(req) {
					b.Fatal("fixture should not match; the loop must run to completion")
				}
			}
		})
	}
}
