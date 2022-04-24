package middleware

import (
	"context"
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

type scopeKey string

// RequestScopeKey uses a typed string to reduce likelihood of clashing
// with other context keys
const RequestScopeKey scopeKey = "request-scope"

// RequestScope contains information regarding the request that is being made.
// The RequestScope is used to pass information between different middlewares
// within the chain.
type RequestScope struct {
	// Authorization is used to indicate if the requset has been authorized
	// by an authorizer earlier in the request chain.
	Authorization Authorization

	// ReverseProxy tracks whether OAuth2-Proxy is operating in reverse proxy
	// mode and if request `X-Forwarded-*` headers should be trusted
	ReverseProxy bool

	// RequestID is set to the request's `X-Request-Id` header if set.
	// Otherwise a random UUID is set.
	RequestID string

	// Session details the authenticated users information (if it exists).
	Session *sessions.SessionState

	// SaveSession indicates whether the session storage should attempt to save
	// the session or not.
	SaveSession bool

	// ClearSession indicates whether the user should be logged out or not.
	ClearSession bool

	// SessionRevalidated indicates whether the session has been revalidated since
	// it was loaded or not.
	SessionRevalidated bool

	// Upstream tracks which upstream was used for this request
	Upstream string
}

// Authorization contains information about the Authorization of a particular
// request.
type Authorization struct {
	// Type is the type of authorization.
	// Valid values are: Request.
	Type AuthorizationType

	// Policy is the authorization policy to apply to this request
	// given the authorization type.
	// Valid values are Allow, Delegate, Deny or omitted.
	// When omitted the caller should decide how to handle this.
	Policy AuthorizationPolicy

	// Message is a message set by the authorizer.
	// This can contain any information about the authorization decision.
	// It may contain success or failure indications.
	Message string
}

// AuthorizationType is a type of authorization for the request.
type AuthorizationType string

const (
	// RequestAuthorization indicates that the request was authorized
	// based on the request based authorization. For example via an allowed route
	// or allow IP combination.
	RequestAuthorization AuthorizationType = "Request"
)

// AuthorizationPolicy is the policy to apply based on the authorization type.
type AuthorizationPolicy string

const (
	// AllowPolicy indicates the request should be allowed.
	AllowPolicy AuthorizationPolicy = "Allow"

	// DelegatePolicy indicates the authorization should be delegated to a later
	// authorizer.
	DelegatePolicy AuthorizationPolicy = "Delegate"

	// DenyPolicy indicates the request should be denied.
	DenyPolicy AuthorizationPolicy = "Deny"

	// OmittedPolicy is the default policy. This should not be set explicitly
	// but can be used to determine that the authorization has not yet been
	// completed.
	OmittedPolicy AuthorizationPolicy = ""
)

// GetRequestScope returns the current request scope from the given request
func GetRequestScope(req *http.Request) *RequestScope {
	scope := req.Context().Value(RequestScopeKey)
	if scope == nil {
		return nil
	}

	return scope.(*RequestScope)
}

// AddRequestScope adds a RequestScope to a request
func AddRequestScope(req *http.Request, scope *RequestScope) *http.Request {
	ctx := context.WithValue(req.Context(), RequestScopeKey, scope)
	return req.WithContext(ctx)
}
