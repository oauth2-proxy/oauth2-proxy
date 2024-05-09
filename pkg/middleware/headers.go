package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/justinas/alice"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/header"
)

func NewRequestHeaderInjector(headers []options.Header) (alice.Constructor, error) {
	headerInjector, err := newRequestHeaderInjector(headers)
	if err != nil {
		return nil, fmt.Errorf("error building request header injector: %v", err)
	}

	strip := newStripHeaders(headers)
	if strip != nil {
		return alice.New(strip, headerInjector).Then, nil
	}
	return headerInjector, nil
}

func newStripHeaders(headers []options.Header) alice.Constructor {
	headersToStrip := []string{}
	for _, header := range headers {
		if !header.PreserveRequestValue {
			headersToStrip = append(headersToStrip, header.Name)
		}
	}

	if len(headersToStrip) == 0 {
		return nil
	}

	return func(next http.Handler) http.Handler {
		return stripHeaders(headersToStrip, next)
	}
}

func flattenHeaders(headers http.Header) {
	for name, values := range headers {
		// Set-Cookie should not be flattened, ref: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
		if len(values) > 1 && name != "Set-Cookie" {
			headers.Set(name, strings.Join(values, ","))
		}
	}
}

func stripHeaders(headers []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		for _, header := range headers {
			req.Header.Del(header)
		}
		next.ServeHTTP(rw, req)
	})
}

func newRequestHeaderInjector(headers []options.Header) (alice.Constructor, error) {
	injector, err := header.NewInjector(headers)
	if err != nil {
		return nil, fmt.Errorf("error building request injector: %v", err)
	}

	return func(next http.Handler) http.Handler {
		return injectRequestHeaders(injector, next)
	}, nil
}

func injectRequestHeaders(injector header.Injector, next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		scope := middlewareapi.GetRequestScope(req)

		// If scope is nil, this will panic.
		// A scope should always be injected before this handler is called.
		injector.Inject(req.Header, scope)
		flattenHeaders(req.Header)
		next.ServeHTTP(rw, req)
	})
}

func NewResponseHeaderInjector(headers []options.Header) (alice.Constructor, error) {
	headerInjector, err := newResponseHeaderInjector(headers)
	if err != nil {
		return nil, fmt.Errorf("error building response header injector: %v", err)
	}

	return headerInjector, nil
}

func newResponseHeaderInjector(headers []options.Header) (alice.Constructor, error) {
	injector, err := header.NewInjector(headers)
	if err != nil {
		return nil, fmt.Errorf("error building response injector: %v", err)
	}

	return func(next http.Handler) http.Handler {
		return injectResponseHeaders(injector, next)
	}, nil
}

func injectResponseHeaders(injector header.Injector, next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		scope := middlewareapi.GetRequestScope(req)

		// If scope is nil, this will panic.
		// A scope should always be injected before this handler is called.
		injector.Inject(rw.Header(), scope)
		flattenHeaders(rw.Header())
		next.ServeHTTP(rw, req)
	})
}
