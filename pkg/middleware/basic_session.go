package middleware

import (
	"fmt"
	"net/http"

	"github.com/justinas/alice"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/authentication/basic"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
)

func NewBasicAuthSessionLoader(validator basic.Validator) alice.Constructor {
	return func(next http.Handler) http.Handler {
		return loadBasicAuthSession(validator, next)
	}
}

// loadBasicAuthSession attmepts to load a session from basic auth credentials
// stored in an Authorization header within the request.
// If no authorization header is found, or the header is invalid, no session
// will be loaded and the request will be passed to the next handler.
// If a session was loaded by a previous handler, it will not be replaced.
func loadBasicAuthSession(validator basic.Validator, next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		scope := middlewareapi.GetRequestScope(req)
		// If scope is nil, this will panic.
		// A scope should always be injected before this handler is called.
		if scope.Session != nil {
			// The session was already loaded, pass to the next handler
			next.ServeHTTP(rw, req)
			return
		}

		session, err := getBasicSession(validator, req)
		if err != nil {
			logger.Errorf("Error retrieving session from token in Authorization header: %v", err)
		}

		// Add the session to the scope if it was found
		scope.Session = session
		next.ServeHTTP(rw, req)
	})
}

// getBasicSession attempts to load a basic session from the request.
// If the credentials in the request exist within the htpasswdMap,
// a new session will be created.
func getBasicSession(validator basic.Validator, req *http.Request) (*sessionsapi.SessionState, error) {
	auth := req.Header.Get("Authorization")
	if auth == "" {
		// No auth header provided, so don't attempt to load a session
		return nil, nil
	}

	user, password, err := findBasicCredentialsFromHeader(auth)
	if err != nil {
		return nil, err
	}

	if validator.Validate(user, password) {
		logger.PrintAuthf(user, req, logger.AuthSuccess, "Authenticated via basic auth and HTpasswd File")
		return &sessionsapi.SessionState{User: user}, nil
	}

	logger.PrintAuthf(user, req, logger.AuthFailure, "Invalid authentication via basic auth: not in Htpasswd File")
	return nil, nil
}

// findBasicCredentialsFromHeader finds basic auth credneitals from the
// Authorization header of a given request.
func findBasicCredentialsFromHeader(header string) (string, string, error) {
	tokenType, token, err := splitAuthHeader(header)
	if err != nil {
		return "", "", err
	}

	if tokenType != "Basic" {
		return "", "", fmt.Errorf("invalid Authorization header: %q", header)
	}

	user, password, err := getBasicAuthCredentials(token)
	if err != nil {
		return "", "", fmt.Errorf("error decoding basic auth credentials: %v", err)
	}

	return user, password, nil
}
