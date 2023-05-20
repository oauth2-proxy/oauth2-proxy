package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"github.com/justinas/alice"
	middlewareapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/middleware"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	k8serrors "k8s.io/apimachinery/pkg/util/errors"
)

const jwtRegexFormat = `^ey[IJ][a-zA-Z0-9_-]*\.ey[IJ][a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]+$`

func NewJwtSessionLoader(sessionLoaders []middlewareapi.TokenToSessionFunc) alice.Constructor {
	regex := regexp.MustCompile(jwtRegexFormat)
	js := &tokenSessionLoader{
		sessionLoaders: sessionLoaders,
		validate:       regex.MatchString,
	}
	return js.loadSession
}

func NewRefreshTokenSessionLoader(sessionLoaders []middlewareapi.TokenToSessionFunc) alice.Constructor {
	js := &tokenSessionLoader{
		sessionLoaders: sessionLoaders,
		// From observations, not all providers use JWT for refresh tokens,
		// some provide an opaque string, so we can't really validate the token at this point
		validate: func(string) bool { return true },
	}
	return js.loadSession
}

// tokenSessionLoader is responsible for loading sessions from tokens in
// Authorization headers.
type tokenSessionLoader struct {
	sessionLoaders []middlewareapi.TokenToSessionFunc
	validate       func(string) bool
}

// loadSession attempts to load a session from a JWT stored in an Authorization
// header within the request.
// If no authorization header is found, or the header is invalid, no session
// will be loaded and the request will be passed to the next handler.
// If a session was loaded by a previous handler, it will not be replaced.
func (t *tokenSessionLoader) loadSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		scope := middlewareapi.GetRequestScope(req)
		// If scope is nil, this will panic.
		// A scope should always be injected before this handler is called.
		if scope.Session != nil {
			// The session was already loaded, pass to the next handler
			next.ServeHTTP(rw, req)
			return
		}

		session, err := t.getTokenSession(req)
		if err != nil {
			logger.Errorf("Error retrieving session from token in Authorization header: %v", err)
		}

		// Add the session to the scope if it was found
		scope.Session = session
		next.ServeHTTP(rw, req)
	})
}

// getJwtSession loads a session based on a JWT token in the authorization header.
// (see the config options skip-jwt-bearer-tokens and extra-jwt-issuers)
func (t *tokenSessionLoader) getTokenSession(req *http.Request) (*sessionsapi.SessionState, error) {
	auth := req.Header.Get("Authorization")
	if auth == "" {
		// No auth header provided, so don't attempt to load a session
		return nil, nil
	}

	token, err := t.findTokenFromHeader(auth)
	if err != nil {
		return nil, err
	}

	// This leading error message only occurs if all session loaders fail
	errs := []error{errors.New("unable to verify bearer token")}
	for _, loader := range t.sessionLoaders {
		session, err := loader(req.Context(), token)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		return session, nil
	}

	return nil, k8serrors.NewAggregate(errs)
}

// findTokenFromHeader finds a valid JWT token from the Authorization header of a given request.
func (t *tokenSessionLoader) findTokenFromHeader(header string) (string, error) {
	tokenType, token, err := splitAuthHeader(header)
	if err != nil {
		return "", err
	}

	if tokenType == "Bearer" && t.validate(token) {
		// Found a JWT as a bearer token
		return token, nil
	}

	if tokenType == "Basic" {
		// Check if we have a Bearer token masquerading in Basic
		return t.getBasicToken(token)
	}

	return "", fmt.Errorf("no valid bearer token found in authorization header")
}

// getBasicToken tries to extract a token from the basic value provided.
func (t *tokenSessionLoader) getBasicToken(token string) (string, error) {
	user, password, err := getBasicAuthCredentials(token)
	if err != nil {
		return "", err
	}

	// check user, user+password, or just password for a token
	if t.validate(user) {
		// Support blank passwords or magic `x-oauth-basic` passwords - nothing else
		/* #nosec G101 */
		if password == "" || password == "x-oauth-basic" {
			return user, nil
		}
	} else if t.validate(token) {
		// support passwords and ignore user
		return password, nil
	}

	return "", fmt.Errorf("invalid basic auth token found in authorization header")
}
